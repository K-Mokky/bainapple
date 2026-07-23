"""Notification center: unread alerts for favorites and incoming DMs.

Security controls:
- All routes require authentication; every query is scoped to the session
  user, so nobody can read or mark another user's notifications.
- Notification content is rendered with Jinja autoescape (page) and DOM
  textContent (live toast), so user-controlled text cannot inject HTML.
- The live push goes to the private ``user:<id>`` SocketIO room that only the
  authenticated owner joins (see chat.handle_connect).
- Target URLs are built server-side with url_for from stored ids — no
  user-controlled URL ever reaches a template or the client.
"""
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, g, redirect, render_template, url_for

from . import socketio
from .db import execute, new_id, query_all, query_one
from .security import login_required

bp = Blueprint("notifications", __name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def user_room(user_id: str) -> str:
    """Private per-user SocketIO room (joined on connect, owner only)."""
    return f"user:{user_id}"


def unread_count(user_id: str) -> int:
    return query_one(
        "SELECT COUNT(*) AS c FROM notification WHERE user_id = ? AND is_read = 0",
        (user_id,),
    )["c"]


def _target_url(ntype: str, actor_id: str, product_id):
    if ntype == "favorite" and product_id:
        return url_for("products.view_product", product_id=product_id)
    return url_for("chat.direct", user_id=actor_id)


def notify(user_id: str, ntype: str, actor, content: str, product_id: str = None):
    """Record a notification for ``user_id`` and push it over SocketIO.

    ``actor`` is the acting user's row (id/username). An existing *unread*
    notification for the same (type, actor, product) is refreshed in place so
    e.g. a chat burst or repeated favorite toggling doesn't flood the list.
    """
    now = _now()
    cur = execute(
        "UPDATE notification SET content = ?, created_at = ?"
        " WHERE user_id = ? AND type = ? AND actor_id = ? AND product_id IS ?"
        " AND is_read = 0",
        (content, now, user_id, ntype, actor["id"], product_id),
    )
    if cur.rowcount == 0:
        execute(
            "INSERT INTO notification"
            " (id, user_id, type, actor_id, product_id, content, is_read, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (new_id(), user_id, ntype, actor["id"], product_id, content, now),
        )
    socketio.emit(
        "notification",
        {
            "type": ntype,
            "username": actor["username"],
            "content": content,
            "created_at": now,
            "url": _target_url(ntype, actor["id"], product_id),
            "unread_count": unread_count(user_id),
        },
        to=user_room(user_id),
    )


@bp.route("/notifications")
@login_required
def list_notifications():
    rows = query_all(
        "SELECT n.id, n.type, n.actor_id, n.product_id, n.content, n.created_at,"
        "       u.username"
        " FROM notification n JOIN user u ON u.id = n.actor_id"
        " WHERE n.user_id = ? AND n.is_read = 0"
        " ORDER BY n.created_at DESC, n.rowid DESC",
        (g.user["id"],),
    )
    notifications = [
        {**dict(r), "url": _target_url(r["type"], r["actor_id"], r["product_id"])}
        for r in rows
    ]
    return render_template("notifications.html", notifications=notifications)


@bp.route("/notifications/<notification_id>/read", methods=["POST"])
@login_required
def read_one(notification_id) -> Response:
    cur = execute(
        "UPDATE notification SET is_read = 1 WHERE id = ? AND user_id = ?",
        (notification_id, g.user["id"]),
    )
    if cur.rowcount == 0:
        abort(404)
    return redirect(url_for("notifications.list_notifications"))


@bp.route("/notifications/read-all", methods=["POST"])
@login_required
def read_all() -> Response:
    execute(
        "UPDATE notification SET is_read = 1 WHERE user_id = ? AND is_read = 0",
        (g.user["id"],),
    )
    return redirect(url_for("notifications.list_notifications"))
