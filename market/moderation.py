"""Reporting and automated moderation.

Security / abuse controls:
- Reporting requires authentication.
- ``target_type`` is constrained to {user, product}; the target must exist.
- Self-reporting (a user reporting themselves or their own product) is rejected.
- A UNIQUE(reporter_id, target_type, target_id) constraint prevents a single
  user from inflating the report count against a target.
- When the distinct-reporter count reaches REPORT_BLOCK_THRESHOLD the target is
  automatically moderated: products are blocked, users are set dormant.
"""
import sqlite3
from datetime import datetime, timezone

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .db import get_db, new_id, query_one
from .security import login_required
from .validators import ValidationError, validate_reason

bp = Blueprint("moderation", __name__)

VALID_TARGETS = {"user", "product"}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _target_exists(target_type: str, target_id: str):
    if target_type == "user":
        return query_one("SELECT id FROM user WHERE id = ?", (target_id,))
    return query_one("SELECT id, seller_id FROM product WHERE id = ?", (target_id,))


def _apply_threshold(target_type: str, target_id: str):
    threshold = current_app.config["REPORT_BLOCK_THRESHOLD"]
    db = get_db()
    count = db.execute(
        "SELECT COUNT(*) AS c FROM report WHERE target_type = ? AND target_id = ?",
        (target_type, target_id),
    ).fetchone()["c"]
    if count < threshold:
        return False
    if target_type == "product":
        db.execute("UPDATE product SET status = 'blocked' WHERE id = ?", (target_id,))
    else:
        db.execute("UPDATE user SET status = 'dormant' WHERE id = ?", (target_id,))
    db.commit()
    return True


@bp.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "GET":
        target_type = request.args.get("target_type", "")
        target_id = request.args.get("target_id", "")
        return render_template(
            "report.html", target_type=target_type, target_id=target_id
        )

    target_type = (request.form.get("target_type") or "").strip()
    target_id = (request.form.get("target_id") or "").strip()

    if target_type not in VALID_TARGETS or not target_id:
        flash("잘못된 신고 대상입니다.")
        return redirect(url_for("main.dashboard"))

    try:
        reason = validate_reason(request.form.get("reason"))
    except ValidationError as exc:
        flash(str(exc))
        return render_template("report.html", target_type=target_type, target_id=target_id)

    target = _target_exists(target_type, target_id)
    if target is None:
        flash("신고 대상을 찾을 수 없습니다.")
        return redirect(url_for("main.dashboard"))

    # Reject self-reporting.
    if target_type == "user" and target_id == g.user["id"]:
        flash("자기 자신을 신고할 수 없습니다.")
        return redirect(url_for("main.dashboard"))
    if target_type == "product" and target["seller_id"] == g.user["id"]:
        flash("자신의 상품은 신고할 수 없습니다.")
        return redirect(url_for("main.dashboard"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (new_id(), g.user["id"], target_type, target_id, reason, _now()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("이미 신고한 대상입니다.")
        return redirect(url_for("main.dashboard"))

    moderated = _apply_threshold(target_type, target_id)
    if moderated:
        flash("신고가 접수되었으며, 누적 신고로 대상이 차단되었습니다.")
    else:
        flash("신고가 접수되었습니다.")
    return redirect(url_for("main.dashboard"))
