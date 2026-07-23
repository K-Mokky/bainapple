"""Security helpers: access-control decorators, request throttling and
response hardening headers.
"""
import time
from collections import defaultdict, deque
from functools import wraps

from flask import (
    abort,
    flash,
    g,
    redirect,
    request,
    session,
    url_for,
)

from .db import query_one


def load_logged_in_user():
    """Attach the current user row to ``g.user`` for each request."""
    user_id = session.get("user_id")
    if user_id is None:
        g.user = None
        return
    g.user = query_one(
        "SELECT id, username, bio, bank_name, account_number, account_holder,"
        "       is_admin, status FROM user WHERE id = ?",
        (user_id,),
    )
    # Session references a deleted or dormant account -> force logout.
    if g.user is None or g.user["status"] != "active":
        session.clear()
        g.user = None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """Admin gate: requires an admin account AND a verified admin key file.

    The key-file check (require.txt §8) means the admin page is reachable only
    from a client that has presented the exact key file; the ``is_admin`` flag
    alone is not sufficient.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        user = g.get("user")
        if user is None:
            flash("로그인이 필요합니다.")
            return redirect(url_for("auth.login", next=request.path))
        if not user["is_admin"]:
            abort(403)
        if not session.get("admin_key_ok"):
            flash("관리자 키 파일 인증이 필요합니다.")
            return redirect(url_for("admin.verify_key", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def apply_security_headers(response):
    """Baseline security headers applied to every response."""
    csp = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self' ws: wss:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers.setdefault("Content-Security-Policy", csp)
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    return response


class RateLimiter:
    """Simple in-memory sliding-window rate limiter.

    Suitable for a single-process deployment / demo. For horizontal scaling a
    shared store (Redis) would be required.
    """

    def __init__(self):
        self._hits = defaultdict(deque)

    def hit(self, key: str, limit: int, window: int) -> bool:
        """Record an event. Return True if within limit, False if exceeded."""
        now = time.monotonic()
        bucket = self._hits[key]
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


class LoginThrottle:
    """Tracks failed login attempts per key and enforces temporary lockout."""

    def __init__(self):
        self._fails = defaultdict(list)  # key -> list[timestamp]

    def is_locked(self, key: str, max_attempts: int, lockout: int) -> bool:
        now = time.monotonic()
        attempts = [t for t in self._fails[key] if now - t < lockout]
        self._fails[key] = attempts
        return len(attempts) >= max_attempts

    def record_failure(self, key: str, lockout: int):
        now = time.monotonic()
        self._fails[key] = [t for t in self._fails[key] if now - t < lockout]
        self._fails[key].append(now)

    def reset(self, key: str):
        self._fails.pop(key, None)


rate_limiter = RateLimiter()
login_throttle = LoginThrottle()
