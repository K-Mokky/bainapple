"""Authentication and user-management routes.

Security controls:
- Passwords are hashed with Werkzeug (pbkdf2/scrypt) + per-user salt.
- Server-side validation on every field (see validators.py).
- Login is throttled per (username, client IP) with temporary lockout.
- Password change requires re-authentication with the current password.
- Dormant accounts cannot log in.
"""
from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from .db import execute, new_id, query_all, query_one
from datetime import datetime, timezone

from .security import (
    client_ip,
    is_safe_next,
    login_required,
    login_throttle,
    rate_limiter,
)
from .validators import (
    ValidationError,
    validate_bio,
    validate_password,
    validate_username,
)

bp = Blueprint("auth", __name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.get("user") is not None:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        cfg = current_app.config
        if not current_app.testing and not rate_limiter.hit(
            f"register:{client_ip()}",
            cfg["REGISTER_MAX_ATTEMPTS"],
            cfg["REGISTER_WINDOW_SECONDS"],
        ):
            flash("요청이 너무 많습니다. 잠시 후 다시 시도해주세요.")
            return render_template("register.html")
        try:
            username = validate_username(request.form.get("username"))
            password = validate_password(request.form.get("password"))
            confirm = request.form.get("confirm", "")
        except ValidationError as exc:
            flash(str(exc))
            return render_template("register.html")
        if password != confirm:
            flash("비밀번호 확인이 일치하지 않습니다.")
            return render_template("register.html")
        if query_one("SELECT 1 FROM user WHERE username = ?", (username,)):
            flash("이미 존재하는 사용자명입니다.")
            return render_template("register.html")
        execute(
            "INSERT INTO user (id, username, password_hash, bio, is_admin, status, created_at)"
            " VALUES (?, ?, ?, '', 0, 'active', ?)",
            (new_id(), username, generate_password_hash(password), _now()),
        )
        flash("회원가입이 완료되었습니다. 로그인 해주세요.")
        return redirect(url_for("auth.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.get("user") is not None:
        return redirect(url_for("main.dashboard"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        cfg = current_app.config
        throttle_key = f"{username}|{client_ip()}"

        if login_throttle.is_locked(
            throttle_key, cfg["LOGIN_MAX_ATTEMPTS"], cfg["LOGIN_LOCKOUT_SECONDS"]
        ):
            flash("로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.")
            return render_template("login.html")

        user = query_one(
            "SELECT id, password_hash, status FROM user WHERE username = ?",
            (username,),
        )
        # Constant-ish behaviour: always run a hash check to reduce user enumeration.
        stored = user["password_hash"] if user else (
            "pbkdf2:sha256:600000$invalid$0000000000000000000000000000000000000000000000000000000000000000"
        )
        ok = check_password_hash(stored, password)

        if not user or not ok:
            login_throttle.record_failure(throttle_key, cfg["LOGIN_LOCKOUT_SECONDS"])
            flash("아이디 또는 비밀번호가 올바르지 않습니다.")
            return render_template("login.html")

        if user["status"] != "active":
            flash("휴면 계정입니다. 관리자에게 문의하세요.")
            return render_template("login.html")

        login_throttle.reset(throttle_key)
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        flash("로그인 되었습니다.")
        nxt = request.args.get("next")
        if is_safe_next(nxt):
            return redirect(nxt)
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("로그아웃 되었습니다.")
    return redirect(url_for("main.index"))


@bp.route("/profile")
@login_required
def profile():
    user = query_one(
        "SELECT id, username, bio, is_admin, status, created_at FROM user WHERE id = ?",
        (g.user["id"],),
    )
    my_products = query_all(
        "SELECT id, title, price, status FROM product WHERE seller_id = ? ORDER BY created_at DESC",
        (g.user["id"],),
    )
    return render_template("profile.html", user=user, my_products=my_products)


@bp.route("/profile/bio", methods=["POST"])
@login_required
def update_bio():
    try:
        bio = validate_bio(request.form.get("bio"))
    except ValidationError as exc:
        flash(str(exc))
        return redirect(url_for("auth.profile"))
    execute("UPDATE user SET bio = ? WHERE id = ?", (bio, g.user["id"]))
    flash("소개글이 업데이트되었습니다.")
    return redirect(url_for("auth.profile"))


@bp.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password") or ""
    row = query_one("SELECT password_hash FROM user WHERE id = ?", (g.user["id"],))
    if not check_password_hash(row["password_hash"], current):
        flash("현재 비밀번호가 올바르지 않습니다.")
        return redirect(url_for("auth.profile"))
    try:
        new_password = validate_password(request.form.get("new_password"))
    except ValidationError as exc:
        flash(str(exc))
        return redirect(url_for("auth.profile"))
    if request.form.get("new_password") != request.form.get("confirm_password"):
        flash("새 비밀번호 확인이 일치하지 않습니다.")
        return redirect(url_for("auth.profile"))
    execute(
        "UPDATE user SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_password), g.user["id"]),
    )
    # Force re-login after a credential change.
    session.clear()
    flash("비밀번호가 변경되었습니다. 다시 로그인 해주세요.")
    return redirect(url_for("auth.login"))


@bp.route("/users")
@login_required
def users():
    q = (request.args.get("q") or "").strip()
    if q:
        rows = query_all(
            "SELECT id, username, bio, status FROM user WHERE username LIKE ? ORDER BY username LIMIT 100",
            (f"%{q}%",),
        )
    else:
        rows = query_all(
            "SELECT id, username, bio, status FROM user ORDER BY username LIMIT 100"
        )
    return render_template("users.html", users=rows, q=q)


@bp.route("/user/<user_id>")
@login_required
def user_profile(user_id):
    user = query_one(
        "SELECT id, username, bio, status, is_admin FROM user WHERE id = ?",
        (user_id,),
    )
    if user is None:
        flash("사용자를 찾을 수 없습니다.")
        return redirect(url_for("auth.users"))
    products = query_all(
        "SELECT id, title, price FROM product WHERE seller_id = ? AND status = 'active'"
        " ORDER BY created_at DESC",
        (user_id,),
    )
    return render_template("user.html", user=user, products=products)
