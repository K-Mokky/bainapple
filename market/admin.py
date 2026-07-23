"""Administrative management panel.

Access control (require.txt §8):
- The admin holds a key file (generated at first startup, path configured by
  ``ADMIN_KEY_FILE``). Every admin route additionally requires that the key
  file has been presented in this session (``/admin/key`` upload); comparison
  uses ``hmac.compare_digest`` (constant time).
- Every route is guarded by ``admin_required`` (is_admin RBAC + key session).
- All mutations are POST + CSRF protected.
- An admin cannot set their own account dormant or delete themselves, to avoid
  self-lockout / accidental privilege loss.

Oversight:
- Users, products and reports are manageable; 1:1 chats are observable
  (require.txt §8 "채팅 또한 관리 관찰").
"""
import hmac

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .db import execute, query_all, query_one
from .security import admin_required, is_safe_next

bp = Blueprint("admin", __name__, url_prefix="/admin")

_KEY_MAX_BYTES = 4096


# ------------------------------------------------------------- key gate
@bp.route("/key", methods=["GET", "POST"])
def verify_key():
    """Key-file gate. Deliberately NOT behind admin_required (it is the gate)."""
    user = g.get("user")
    if user is None:
        flash("로그인이 필요합니다.")
        return redirect(url_for("auth.login", next=request.path))
    if not user["is_admin"]:
        abort(403)
    if request.method == "POST":
        uploaded = request.files.get("key_file")
        if uploaded is None or not uploaded.filename:
            flash("키 파일을 선택해주세요.")
            return render_template("admin/key.html")
        submitted = uploaded.read(_KEY_MAX_BYTES).decode("utf-8", "ignore").strip()
        try:
            with open(current_app.config["ADMIN_KEY_FILE"], encoding="utf-8") as fh:
                expected = fh.read().strip()
        except OSError:
            expected = ""
        if expected and hmac.compare_digest(submitted, expected):
            session["admin_key_ok"] = True
            flash("관리자 키가 확인되었습니다.")
            nxt = request.args.get("next")
            if is_safe_next(nxt):
                return redirect(nxt)
            return redirect(url_for("admin.dashboard"))
        flash("키 파일이 올바르지 않습니다.")
    return render_template("admin/key.html")


@bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": query_one("SELECT COUNT(*) c FROM user")["c"],
        "dormant": query_one("SELECT COUNT(*) c FROM user WHERE status='dormant'")["c"],
        "products": query_one("SELECT COUNT(*) c FROM product")["c"],
        "blocked": query_one("SELECT COUNT(*) c FROM product WHERE status='blocked'")["c"],
        "reports": query_one("SELECT COUNT(*) c FROM report")["c"],
        "dms": query_one("SELECT COUNT(*) c FROM dm")["c"],
    }
    return render_template("admin/dashboard.html", stats=stats)


# ---------------------------------------------------------------- users
@bp.route("/users")
@admin_required
def users():
    q = (request.args.get("q") or "").strip()
    if q:
        rows = query_all(
            "SELECT id, username, is_admin, status FROM user"
            " WHERE username LIKE ? ORDER BY username LIMIT 200",
            (f"%{q}%",),
        )
    else:
        rows = query_all(
            "SELECT id, username, is_admin, status FROM user"
            " ORDER BY username LIMIT 200"
        )
    return render_template("admin/users.html", users=rows, q=q)


@bp.route("/user/<user_id>/dormant", methods=["POST"])
@admin_required
def set_dormant(user_id):
    if user_id == g.user["id"]:
        flash("자기 자신을 휴면 처리할 수 없습니다.")
        return redirect(url_for("admin.users"))
    execute("UPDATE user SET status='dormant' WHERE id=?", (user_id,))
    flash("사용자를 휴면 처리했습니다.")
    return redirect(url_for("admin.users"))


@bp.route("/user/<user_id>/restore", methods=["POST"])
@admin_required
def restore_user(user_id):
    execute("UPDATE user SET status='active' WHERE id=?", (user_id,))
    flash("사용자를 활성화했습니다.")
    return redirect(url_for("admin.users"))


@bp.route("/user/<user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == g.user["id"]:
        flash("자기 자신을 삭제할 수 없습니다.")
        return redirect(url_for("admin.users"))
    execute("DELETE FROM user WHERE id=?", (user_id,))
    flash("사용자를 삭제했습니다.")
    return redirect(url_for("admin.users"))


# ------------------------------------------------------------- products
@bp.route("/products")
@admin_required
def products():
    q = (request.args.get("q") or "").strip()
    if q:
        rows = query_all(
            "SELECT p.id, p.title, p.price, p.status, p.sale_status, u.username AS seller"
            " FROM product p JOIN user u ON u.id = p.seller_id"
            " WHERE p.title LIKE ? ORDER BY p.created_at DESC LIMIT 200",
            (f"%{q}%",),
        )
    else:
        rows = query_all(
            "SELECT p.id, p.title, p.price, p.status, p.sale_status, u.username AS seller"
            " FROM product p JOIN user u ON u.id = p.seller_id"
            " ORDER BY p.created_at DESC LIMIT 200"
        )
    return render_template("admin/products.html", products=rows, q=q)


@bp.route("/product/<product_id>/block", methods=["POST"])
@admin_required
def block_product(product_id):
    execute("UPDATE product SET status='blocked' WHERE id=?", (product_id,))
    flash("상품을 차단했습니다.")
    return redirect(url_for("admin.products"))


@bp.route("/product/<product_id>/unblock", methods=["POST"])
@admin_required
def unblock_product(product_id):
    execute("UPDATE product SET status='active' WHERE id=?", (product_id,))
    flash("상품 차단을 해제했습니다.")
    return redirect(url_for("admin.products"))


@bp.route("/product/<product_id>/delete", methods=["POST"])
@admin_required
def delete_product(product_id):
    execute("DELETE FROM product WHERE id=?", (product_id,))
    flash("상품을 삭제했습니다.")
    return redirect(url_for("admin.products"))


# -------------------------------------------------------------- reports
@bp.route("/reports")
@admin_required
def reports():
    rows = query_all(
        "SELECT r.id, r.target_type, r.target_id, r.reason, r.created_at,"
        "       u.username AS reporter"
        " FROM report r JOIN user u ON u.id = r.reporter_id"
        " ORDER BY r.created_at DESC LIMIT 300"
    )
    return render_template("admin/reports.html", reports=rows)


@bp.route("/report/<report_id>/delete", methods=["POST"])
@admin_required
def delete_report(report_id):
    execute("DELETE FROM report WHERE id=?", (report_id,))
    flash("신고를 삭제했습니다.")
    return redirect(url_for("admin.reports"))


# ----------------------------------------------------- chat oversight


@bp.route("/dms")
@admin_required
def dms():
    rows = query_all(
        "SELECT d.content, d.created_at,"
        "       su.username AS sender, ru.username AS receiver"
        " FROM dm d"
        " JOIN user su ON su.id = d.sender_id"
        " JOIN user ru ON ru.id = d.receiver_id"
        " ORDER BY d.created_at DESC LIMIT 300"
    )
    return render_template("admin/dms.html", dms=rows)
