"""Notification center tests: unread alerts for favorites and incoming DMs.

Same conventions as the rest of the suite: shared session-scoped app, unique
usernames per test, DB deltas for independence.
"""
from market import socketio as _socketio
from market.db import query_one


def _uid(app, username):
    with app.app_context():
        return query_one("SELECT id FROM user WHERE username=?", (username,))["id"]


def _add_product(client, title, price="1000"):
    client.post(
        "/product/new",
        data={"title": title, "description": "d", "price": price},
        follow_redirects=True,
    )


def _pid(app, title):
    with app.app_context():
        return query_one("SELECT id FROM product WHERE title=?", (title,))["id"]


def _unread(app, user_id):
    with app.app_context():
        return query_one(
            "SELECT COUNT(*) c FROM notification WHERE user_id=? AND is_read=0",
            (user_id,),
        )["c"]


def test_notifications_require_login(app):
    r = app.test_client().get("/notifications", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers["Location"]


def test_favorite_creates_notification(app, helper):
    seller = helper.user("nfseller")
    _add_product(seller, "NotifFav")
    pid = _pid(app, "NotifFav")
    sid = _uid(app, "nfseller")
    buyer = helper.user("nfbuyer")

    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)
    assert _unread(app, sid) == 1

    r = seller.get("/notifications")
    assert "nfbuyer".encode() in r.data
    assert "NotifFav".encode() in r.data
    assert f"/product/{pid}".encode() in r.data  # links to the product
    # unread badge rendered in the nav (not hidden)
    page = seller.get("/products").data
    assert b'id="notif-badge"' in page
    assert b">1</span>" in page

    # un-favorite then re-favorite refreshes the unread alert instead of stacking
    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)  # off
    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)  # on again
    assert _unread(app, sid) == 1


def test_favorite_socket_push(app, helper):
    seller = helper.user("npseller")
    _add_product(seller, "NotifPush")
    pid = _pid(app, "NotifPush")
    buyer = helper.user("npbuyer")

    ss = _socketio.test_client(app, flask_test_client=seller)  # joins user:<id>
    ss.get_received()
    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)
    notes = [r for r in ss.get_received() if r["name"] == "notification"]
    assert len(notes) == 1
    payload = notes[0]["args"][0]
    assert payload["type"] == "favorite"
    assert payload["username"] == "npbuyer"
    assert "NotifPush" in payload["content"]
    assert payload["url"] == f"/product/{pid}"
    assert payload["unread_count"] == 1
    ss.disconnect()


def test_dm_notification_and_dedupe(app, helper):
    a = helper.user("ndma")
    b = helper.user("ndmb")
    aid, bid = _uid(app, "ndma"), _uid(app, "ndmb")

    sb = _socketio.test_client(app, flask_test_client=b)
    sb.get_received()
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.emit("dm_message", {"peer_id": bid, "message": "first"})
    sa.emit("dm_message", {"peer_id": bid, "message": "second"})
    sa.disconnect()

    # receiver got live pushes with a chat link
    notes = [r for r in sb.get_received() if r["name"] == "notification"]
    assert len(notes) == 2
    assert notes[-1]["args"][0]["type"] == "dm"
    assert notes[-1]["args"][0]["url"] == f"/chat/{aid}"
    sb.disconnect()

    # unread alerts from the same sender collapse into one, keeping the latest
    assert _unread(app, bid) == 1
    with app.app_context():
        row = query_one(
            "SELECT content FROM notification WHERE user_id=? AND is_read=0", (bid,)
        )
    assert row["content"] == "second"
    r = b.get("/notifications")
    assert b"second" in r.data
    assert f"/chat/{aid}".encode() in r.data


def test_mark_read_one_and_all(app, helper):
    a = helper.user("nreada")
    b = helper.user("nreadb")
    bid = _uid(app, "nreadb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.emit("dm_message", {"peer_id": bid, "message": "unread me"})
    sa.disconnect()
    assert _unread(app, bid) == 1

    with app.app_context():
        nid = query_one(
            "SELECT id FROM notification WHERE user_id=? AND is_read=0", (bid,)
        )["id"]

    # another user cannot mark someone else's notification
    intruder = helper.user("nreadc")
    assert intruder.post(f"/notifications/{nid}/read").status_code == 404
    assert _unread(app, bid) == 1

    b.post(f"/notifications/{nid}/read", follow_redirects=True)
    assert _unread(app, bid) == 0

    # read-all clears everything at once
    sa2 = _socketio.test_client(app, flask_test_client=a)
    sa2.emit("send_account", {"peer_id": bid})  # no account -> no notification
    sa2.emit("dm_message", {"peer_id": bid, "message": "again"})
    sa2.disconnect()
    assert _unread(app, bid) == 1
    r = b.post("/notifications/read-all", follow_redirects=True)
    assert "읽지 않은 알림이 없습니다".encode() in r.data
    assert _unread(app, bid) == 0


def test_notification_content_escaped(app, helper):
    a = helper.user("nxssa")
    b = helper.user("nxssb")
    bid = _uid(app, "nxssb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.emit("dm_message", {"peer_id": bid, "message": "<script>evil()</script>"})
    sa.disconnect()
    r = b.get("/notifications")
    assert b"<script>evil()</script>" not in r.data
    assert b"&lt;script&gt;" in r.data
