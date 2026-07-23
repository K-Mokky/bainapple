"""Real-time 1:1 chat (DM) with a per-user conversation list.

Security controls:
- Every socket event requires an authenticated session; unauthenticated
  events are dropped.
- Messages are validated (length/content) server-side; output paths escape
  them (Jinja autoescape for history, DOM textContent on the client).
- Per-user sliding-window rate limiting mitigates spam/flooding.
- 1:1 rooms are derived from the sorted pair of user ids, so a user can only
  ever receive DMs addressed to a room they belong to.
- On connect each user silently joins a private ``user:<id>`` room used for
  conversation-list notifications; nobody else can join it.
"""
from datetime import datetime, timezone

from flask import Blueprint, abort, current_app, g, render_template, session
from flask_socketio import emit, join_room

from . import socketio
from .db import execute, new_id, query_all, query_one
from .security import login_required, rate_limiter
from .validators import ValidationError, validate_message
from .notifications import notify, user_room as _user_room

bp = Blueprint("chat", __name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _dm_room(a: str, b: str) -> str:
    return "dm:" + "|".join(sorted([a, b]))


# Prefix marking a bank-account DM (require.txt §6). The client renders these
# messages as click-to-copy; clicking copies bank/account/holder to clipboard.
ACCOUNT_PREFIX = "[계좌정보]"


# ----------------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------------
@bp.route("/chat")
@login_required
def chat_list():
    """List of 1:1 conversations, newest first.

    A conversation exists as soon as either side has sent a DM, so when a
    buyer first contacts a seller the room appears in the seller's list.
    """
    me = g.user["id"]
    conversations = query_all(
        """
        SELECT u.id AS peer_id, u.username, t.content, t.created_at
        FROM (
            SELECT CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END AS peer_id,
                   content, created_at,
                   ROW_NUMBER() OVER (
                       PARTITION BY CASE WHEN sender_id = ? THEN receiver_id ELSE sender_id END
                       ORDER BY created_at DESC, rowid DESC
                   ) AS rn
            FROM dm
            WHERE sender_id = ? OR receiver_id = ?
        ) t
        JOIN user u ON u.id = t.peer_id
        WHERE t.rn = 1
        ORDER BY t.created_at DESC
        """,
        (me, me, me, me),
    )
    return render_template("chat.html", conversations=conversations)


@bp.route("/chat/<user_id>")
@login_required
def direct(user_id):
    if user_id == g.user["id"]:
        abort(400)
    peer = query_one("SELECT id, username FROM user WHERE id = ?", (user_id,))
    if peer is None:
        abort(404)
    history = query_all(
        "SELECT sender_id, content, created_at FROM dm"
        " WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)"
        " ORDER BY created_at ASC LIMIT 200",
        (g.user["id"], user_id, user_id, g.user["id"]),
    )
    has_account = bool(
        g.user["bank_name"] and g.user["account_number"] and g.user["account_holder"]
    )
    return render_template(
        "dm.html",
        peer=peer,
        history=history,
        me=g.user["id"],
        has_account=has_account,
        account_prefix=ACCOUNT_PREFIX,
    )


# ----------------------------------------------------------------------------
# Socket handlers
# ----------------------------------------------------------------------------
def _current_socket_user():
    """Return the authenticated (id, username) for the socket session or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    row = query_one(
        "SELECT id, username, status FROM user WHERE id = ?", (uid,)
    )
    if row is None or row["status"] != "active":
        return None
    return row


@socketio.on("connect")
def handle_connect():
    """Join the private per-user room used for conversation-list updates."""
    user = _current_socket_user()
    if user is None:
        return
    join_room(_user_room(user["id"]))


@socketio.on("join_dm")
def handle_join_dm(data):
    user = _current_socket_user()
    if user is None:
        return
    peer_id = (data or {}).get("peer_id")
    if not peer_id or peer_id == user["id"]:
        return
    if query_one("SELECT 1 FROM user WHERE id = ?", (peer_id,)) is None:
        return
    join_room(_dm_room(user["id"], peer_id))


def _notify_conversation(sender, peer_id: str, content: str):
    """Tell the receiver's chat list that a conversation was created/updated."""
    socketio.emit(
        "dm_notify",
        {
            "peer_id": sender["id"],
            "username": sender["username"],
            "message": content,
            "created_at": _now(),
        },
        to=_user_room(peer_id),
    )
    # Persist an unread alert and push it to the receiver's notification badge.
    notify(peer_id, "dm", sender, content)


@socketio.on("dm_message")
def handle_dm_message(data):
    user = _current_socket_user()
    if user is None:
        return
    peer_id = (data or {}).get("peer_id")
    if not peer_id or peer_id == user["id"]:
        return
    if query_one("SELECT 1 FROM user WHERE id = ?", (peer_id,)) is None:
        return
    limit = current_app.config["CHAT_MAX_MESSAGES"]
    window = current_app.config["CHAT_WINDOW_SECONDS"]
    if not rate_limiter.hit(f"dm:{user['id']}", limit, window):
        emit("rate_limited", {"scope": "dm"})
        return
    try:
        content = validate_message((data or {}).get("message"))
    except (ValidationError, AttributeError):
        return
    execute(
        "INSERT INTO dm (id, sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), user["id"], peer_id, content, _now()),
    )
    room = _dm_room(user["id"], peer_id)
    socketio.emit(
        "new_dm",
        {"sender_id": user["id"], "message": content, "created_at": _now()},
        to=room,
    )
    _notify_conversation(user, peer_id, content)


@socketio.on("send_account")
def handle_send_account(data):
    """Send the sender's own saved bank account into a 1:1 chat (require.txt §6).

    The account is read from the DB server-side, so a client can only ever
    share the account stored on its own authenticated user row.
    """
    user = _current_socket_user()
    if user is None:
        return
    peer_id = (data or {}).get("peer_id")
    if not peer_id or peer_id == user["id"]:
        return
    if query_one("SELECT 1 FROM user WHERE id = ?", (peer_id,)) is None:
        return
    account = query_one(
        "SELECT bank_name, account_number, account_holder FROM user WHERE id = ?",
        (user["id"],),
    )
    if not (account["bank_name"] and account["account_number"] and account["account_holder"]):
        emit("account_missing")
        return
    limit = current_app.config["CHAT_MAX_MESSAGES"]
    window = current_app.config["CHAT_WINDOW_SECONDS"]
    if not rate_limiter.hit(f"dm:{user['id']}", limit, window):
        return
    content = (
        f"{ACCOUNT_PREFIX} {account['bank_name']}"
        f" {account['account_number']} {account['account_holder']}"
    )
    execute(
        "INSERT INTO dm (id, sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (new_id(), user["id"], peer_id, content, _now()),
    )
    socketio.emit(
        "new_dm",
        {
            "sender_id": user["id"],
            "message": content,
            "created_at": _now(),
            "is_account": True,
        },
        to=_dm_room(user["id"], peer_id),
    )
    _notify_conversation(user, peer_id, content)
