"""SocketIO chat (1:1 DM) tests.

They run against the shared session-scoped ``app`` fixture (conftest.py) so the
process performs exactly one Flask-SocketIO initialisation (Flask-SocketIO binds
its JSON codec to the first app). Unique usernames and message-count deltas keep
these tests independent from the rest of the suite.
"""
from market import socketio as _socketio
from market.db import query_one


def _user(app, username):
    c = app.test_client()
    c.post("/register", data={"username": username, "password": "Password1", "confirm": "Password1"})
    c.post("/login", data={"username": username, "password": "Password1"})
    return c


def _uid(app, username):
    with app.app_context():
        return query_one("SELECT id FROM user WHERE username=?", (username,))["id"]


def _dm_count(app):
    with app.app_context():
        return query_one("SELECT COUNT(*) c FROM dm")["c"]


def test_dm_requires_auth(app):
    before = _dm_count(app)
    anon = _socketio.test_client(app)
    anon.emit("dm_message", {"peer_id": "whatever", "message": "hi"})
    anon.disconnect()
    assert _dm_count(app) == before  # unauthenticated message dropped


def test_chat_list_requires_login(app):
    r = app.test_client().get("/chat", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/login" in r.headers["Location"]


def test_chat_list_shows_room_when_buyer_contacts(app):
    """A new conversation appears in the seller's /chat list after the first DM."""
    buyer = _user(app, "listbuyer")
    seller = _user(app, "listseller")
    sid = _uid(app, "listseller")

    r = seller.get("/chat")
    assert b"listbuyer" not in r.data  # no room yet

    sb = _socketio.test_client(app, flask_test_client=buyer)
    sb.emit("dm_message", {"peer_id": sid, "message": "구매 문의합니다"})
    sb.disconnect()

    r = seller.get("/chat")
    assert b"listbuyer" in r.data                       # room appeared
    assert "구매 문의합니다".encode() in r.data            # with last-message preview
    assert f"/chat/{_uid(app, 'listbuyer')}".encode() in r.data


def test_chat_list_live_notify(app):
    """The receiver's chat-list socket gets dm_notify for incoming DMs."""
    a = _user(app, "notifya")
    b = _user(app, "notifyb")
    bid = _uid(app, "notifyb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sb = _socketio.test_client(app, flask_test_client=b)  # connect joins user:<id> room
    sa.get_received(); sb.get_received()
    sa.emit("dm_message", {"peer_id": bid, "message": "ping"})
    notes = [r for r in sb.get_received() if r["name"] == "dm_notify"]
    assert len(notes) == 1
    assert notes[0]["args"][0]["username"] == "notifya"
    assert notes[0]["args"][0]["message"] == "ping"
    sa.disconnect(); sb.disconnect()


def test_dm_xss_stored_raw_escaped_on_render(app):
    a = _user(app, "xssa")
    _user(app, "xssb")
    bid = _uid(app, "xssb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.emit("dm_message", {"peer_id": bid, "message": "<script>x</script>"})
    sa.disconnect()
    r = a.get(f"/chat/{bid}")
    assert b"<script>x</script>" not in r.data
    assert b"&lt;script&gt;" in r.data
    # chat list preview is escaped too
    r = a.get("/chat")
    assert b"<script>x</script>" not in r.data


def test_dm_isolation(app):
    a = _user(app, "dma")
    b = _user(app, "dmb")
    c = _user(app, "dmc")
    aid, bid = _uid(app, "dma"), _uid(app, "dmb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sb = _socketio.test_client(app, flask_test_client=b)
    sc = _socketio.test_client(app, flask_test_client=c)
    sa.emit("join_dm", {"peer_id": bid})
    sb.emit("join_dm", {"peer_id": aid})
    sa.get_received(); sb.get_received(); sc.get_received()
    sa.emit("dm_message", {"peer_id": bid, "message": "secret"})
    assert len([r for r in sb.get_received() if r["name"] == "new_dm"]) == 1
    assert len([r for r in sc.get_received() if r["name"] == "new_dm"]) == 0
    sa.disconnect(); sb.disconnect(); sc.disconnect()


def test_dm_rate_limit(app):
    a = _user(app, "ratea")
    _user(app, "rateb")
    bid = _uid(app, "rateb")
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.get_received()
    for i in range(6):
        sa.emit("dm_message", {"peer_id": bid, "message": f"m{i}"})
    assert len([r for r in sa.get_received() if r["name"] == "rate_limited"]) >= 1
    sa.disconnect()


def test_send_account_via_dm(app):
    a = _user(app, "acca")
    b = _user(app, "accb")
    aid, bid = _uid(app, "acca"), _uid(app, "accb")
    a.post("/wallet/account",
           data={"bank_name": "카카오뱅크", "account_number": "3333-01-1234567", "account_holder": "판매자"})
    sa = _socketio.test_client(app, flask_test_client=a)
    sb = _socketio.test_client(app, flask_test_client=b)
    sa.emit("join_dm", {"peer_id": bid})
    sb.emit("join_dm", {"peer_id": aid})
    sa.get_received(); sb.get_received()
    sa.emit("send_account", {"peer_id": bid})
    got = [r for r in sb.get_received() if r["name"] == "new_dm"]
    assert len(got) == 1
    payload = got[0]["args"][0]
    assert payload["is_account"] is True
    assert "카카오뱅크" in payload["message"]
    assert "3333-01-1234567" in payload["message"]
    assert "판매자" in payload["message"]
    with app.app_context():
        row = query_one("SELECT content FROM dm WHERE sender_id=? AND receiver_id=?", (aid, bid))
    assert "3333-01-1234567" in row["content"]
    sa.disconnect(); sb.disconnect()


def test_send_account_without_saved_account(app):
    a = _user(app, "noacc")
    _user(app, "noaccpeer")
    bid = _uid(app, "noaccpeer")
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.get_received()
    sa.emit("send_account", {"peer_id": bid})
    assert any(r["name"] == "account_missing" for r in sa.get_received())
    with app.app_context():
        c = query_one("SELECT COUNT(*) c FROM dm WHERE sender_id=?", (_uid(app, "noacc"),))["c"]
    assert c == 0
    sa.disconnect()
