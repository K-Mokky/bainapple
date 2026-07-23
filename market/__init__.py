"""Application factory for the Tiny Second-hand Shopping Platform.

Wires together configuration, database, CSRF protection, SocketIO, security
middleware, blueprints and error handlers.
"""
import os
from datetime import datetime, timezone
import secrets
import sys

from flask import Flask, g, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

from .config import Config
from .db import close_db, init_db
from .security import apply_security_headers, load_logged_in_user

csrf = CSRFProtect()
socketio = SocketIO()


def _ensure_admin_key_file(app: Flask) -> None:
    """Generate the admin key file on first run (require.txt §8).

    The operator hands this file to the administrator; presenting it at
    /admin/key is the only way to open the admin pages.
    """
    key_path = app.config["ADMIN_KEY_FILE"]
    if os.path.exists(key_path):
        return
    directory = os.path.dirname(key_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(key_path, "w", encoding="utf-8") as fh:
        fh.write(secrets.token_hex(32))
    os.chmod(key_path, 0o600)
    print(f"[INFO] Admin key file generated at {key_path}", file=sys.stderr)


def create_app(config_object: type = Config) -> Flask:
    app = Flask(__name__)
    # Trust exactly one proxy hop (Render's load balancer) so request.scheme /
    # request.remote_addr reflect the forwarded values instead of the internal
    # proxy. Client throttling additionally prefers CF-Connecting-IP; see
    # security.client_ip.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.from_object(config_object)

    if getattr(config_object, "SECRET_KEY_IS_EPHEMERAL", False):
        print(
            "[WARN] SECRET_KEY is not set; using an ephemeral key. "
            "Set SECRET_KEY in the environment for production.",
            file=sys.stderr,
        )

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    _ensure_admin_key_file(app)

    csrf.init_app(app)
    # No cors_allowed_origins => flask-socketio default: same-origin only.
    # (An empty list would mean "no origins allowed" and reject every request
    # that carries an Origin header, i.e. all browser POSTs / WS upgrades.)
    socketio.init_app(app)

    # --- Request lifecycle ---------------------------------------------
    app.teardown_appcontext(close_db)

    @app.before_request
    def _load_user():
        load_logged_in_user()

    @app.after_request
    def _headers(response):
        return apply_security_headers(response)

    @app.context_processor
    def _inject_user():
        from .notifications import unread_count

        user = g.get("user")
        unread = unread_count(user["id"]) if user is not None else 0
        return {"current_user": user, "unread_notifications": unread}

    @app.template_filter("timeago")
    def timeago(value: str) -> str:
        """Relative Korean timestamp for listing cards ("3분 전")."""
        try:
            then = datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return ""
        if then.tzinfo is None:
            then = then.replace(tzinfo=timezone.utc)
        seconds = (datetime.now(timezone.utc) - then).total_seconds()
        if seconds < 60:
            return "방금 전"
        minutes = int(seconds // 60)
        if minutes < 60:
            return f"{minutes}분 전"
        hours = minutes // 60
        if hours < 24:
            return f"{hours}시간 전"
        days = hours // 24
        if days < 30:
            return f"{days}일 전"
        months = days // 30
        if months < 12:
            return f"{months}개월 전"
        return f"{days // 365}년 전"

    @app.template_global()
    def has_endpoint(name: str) -> bool:
        """True when a URL rule exists for ``name`` (nav links degrade safely)."""
        return any(rule.endpoint == name for rule in app.url_map.iter_rules())

    # --- Blueprints -----------------------------------------------------
    from .main import bp as main_bp
    app.register_blueprint(main_bp)

    # Feature blueprints are registered here as each story implements them.
    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    from .products import bp as products_bp
    app.register_blueprint(products_bp)

    # chat imports register the SocketIO event handlers on import.
    from .chat import bp as chat_bp
    app.register_blueprint(chat_bp)

    from .notifications import bp as notifications_bp
    app.register_blueprint(notifications_bp)

    from .wallet import bp as wallet_bp
    app.register_blueprint(wallet_bp)

    from .moderation import bp as moderation_bp
    app.register_blueprint(moderation_bp)

    from .admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    # --- Error handlers (no sensitive info disclosure) ------------------
    @app.errorhandler(400)
    def _bad_request(e):
        return render_template("error.html", code=400, message="잘못된 요청입니다."), 400

    @app.errorhandler(403)
    def _forbidden(e):
        return render_template("error.html", code=403, message="접근 권한이 없습니다."), 403

    @app.errorhandler(404)
    def _not_found(e):
        return render_template("error.html", code=404, message="페이지를 찾을 수 없습니다."), 404

    @app.errorhandler(413)
    def _too_large(e):
        return render_template("error.html", code=413, message="업로드 용량이 너무 큽니다."), 413

    @app.errorhandler(CSRFError)
    def _csrf_error(e):
        return render_template("error.html", code=400, message="CSRF 검증에 실패했습니다."), 400

    @app.errorhandler(500)
    def _server_error(e):
        return render_template("error.html", code=500, message="서버 오류가 발생했습니다."), 500

    with app.app_context():
        init_db()

    return app
