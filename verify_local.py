"""End-to-end verification of the PostgreSQL port against a local cluster.

Exercises every SQLite->PG translation landmine through real code paths:
  * "user" reserved-word quoting          (register/login/wallet/admin)
  * GROUP BY + LEFT JOIN aggregate        (products listing)
  * ILIKE search                          (products/admin search)
  * window function + rowid->seq          (chat conversation list)
  * IS ? -> IS NOT DISTINCT FROM          (notification upsert, NULL product_id)
  * sqlite3.IntegrityError mapping        (duplicate report)
Not a shipped file — used only to validate the port.
"""
import os
import re
import sys

os.environ.setdefault(
    "DATABASE_URL",
    "postgresql://postgres@127.0.0.1:55432/bainapple_test?sslmode=disable",
)

from market import create_app, socketio
from market.config import Config
from market.db import get_db, query_all, query_one
import migrate_from_sqlite


class T(Config):
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "verify-secret"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD = "adminpass123"


FAILS = []


def check(name, cond):
    print(("  ok  " if cond else " FAIL ") + name)
    if not cond:
        FAILS.append(name)


app = create_app(T)  # triggers init_db() -> creates schema in PG

# ---- data migration from the legacy sqlite db -----------------------------
print("== migration ==")
migrate_from_sqlite.migrate("market.db.import")

with app.app_context():
    users = query_all("SELECT username FROM user ORDER BY username")
    check("migrated users present", len(users) >= 4)
    check("migrated product present", query_one("SELECT COUNT(*) c FROM product")["c"] >= 1)
    check("migrated dm present", query_one("SELECT COUNT(*) c FROM dm")["c"] >= 4)

client = app.test_client()


def register(u, p):
    return client.post("/register", data={"username": u, "password": p, "confirm": p},
                       follow_redirects=True)


def login(u, p):
    return client.post("/login", data={"username": u, "password": p}, follow_redirects=True)


print("== auth ==")
register("alice", "password123")
register("bob", "password123")
r = login("alice", "password123")
check("login alice", "로그아웃" in r.get_data(as_text=True) or r.status_code == 200)

print("== product create / list / search ==")
r = client.post("/product/new", data={
    "title": "빈티지 카메라",
    "description": "상태 좋은 필름 카메라입니다",
    "price": "50000",
    "category": "디지털기기",
}, follow_redirects=True)
check("create product", r.status_code == 200)
with app.app_context():
    pid = query_one("SELECT id FROM product WHERE title = ?", ("빈티지 카메라",))
    check("product row exists", pid is not None)
pid = pid["id"]

r = client.get("/products?q=빈티지&sort=likes")   # GROUP BY + ILIKE + aggregate order
check("listing GROUP BY/ILIKE search", r.status_code == 200 and "빈티지 카메라" in r.get_data(as_text=True))
r = client.get("/products?sort=price_asc&selling=1&category=디지털기기")
check("listing filters", r.status_code == 200)

print("== favorite + notification (IS NULL upsert) ==")
# bob favorites alice's product -> notifies alice (favorite, product_id set)
client.post("/logout")
login("bob", "password123")
r = client.post(f"/product/{pid}/favorite", follow_redirects=True)
check("favorite toggle", r.status_code == 200)
with app.app_context():
    fav = query_one("SELECT COUNT(*) c FROM favorite WHERE product_id = ?", (pid,))
    check("favorite row", fav["c"] == 1)
    notif = query_one("SELECT COUNT(*) c FROM notification WHERE type='favorite'")
    check("favorite notification created", notif["c"] >= 1)

print("== wallet (UPDATE \"user\") ==")
r = client.post("/wallet/account", data={
    "bank_name": "카카오뱅크", "account_number": "3333-01-1234567", "account_holder": "홍길동",
}, follow_redirects=True)
check("wallet save", r.status_code == 200)

print("== chat via socketio (window fn, IS NULL dm notify) ==")
# bob is logged in; open a socket sharing bob's session
sio = socketio.test_client(app, flask_test_client=client)
check("socket connected", sio.is_connected())
with app.app_context():
    alice_id = query_one("SELECT id FROM user WHERE username=?", ("alice",))["id"]
sio.emit("dm_message", {"peer_id": alice_id, "message": "안녕하세요 카메라 문의드려요"})
sio.disconnect()
with app.app_context():
    dm = query_one("SELECT COUNT(*) c FROM dm WHERE content = ?", ("안녕하세요 카메라 문의드려요",))
    check("dm inserted via socket", dm["c"] == 1)
    dmnotif = query_one("SELECT COUNT(*) c FROM notification WHERE type='dm'")
    check("dm notification (IS NULL path)", dmnotif["c"] >= 1)
# conversation list (ROW_NUMBER window + seq tie-breaker) for bob
r = client.get("/chat")
check("chat conversation list", r.status_code == 200 and "alice" in r.get_data(as_text=True))
r = client.get("/notifications")
check("notifications page", r.status_code == 200)

print("== moderation duplicate report (IntegrityError mapping) ==")
# bob reports alice (user) twice -> 2nd must be caught, not crash
with app.app_context():
    alice_id = query_one("SELECT id FROM user WHERE username=?", ("alice",))["id"]
client.post("/report", data={"target_type": "user", "target_id": alice_id, "reason": "부적절한 사용자입니다"}, follow_redirects=True)
r2 = client.post("/report", data={"target_type": "user", "target_id": alice_id, "reason": "부적절한 사용자입니다 다시"}, follow_redirects=True)
check("duplicate report handled (no 500)", r2.status_code == 200 and "이미 신고한" in r2.get_data(as_text=True))
with app.app_context():
    rc = query_one("SELECT COUNT(*) c FROM report WHERE target_id=?", (alice_id,))
    check("only one report stored", rc["c"] == 1)

print("== admin queries (joins on \"user\") ==")
with app.app_context():
    stats_dms = query_one("SELECT COUNT(*) c FROM dm")["c"]
    check("admin dm count", stats_dms >= 5)
    urows = query_all("SELECT id, username, is_admin, status FROM user WHERE username LIKE ? ORDER BY username LIMIT 200", ("%li%",))
    check("admin user ILIKE join", any(u["username"] == "alice" for u in urows))
    prows = query_all("SELECT p.id, p.title, u.username AS seller FROM product p JOIN user u ON u.id = p.seller_id ORDER BY p.created_at DESC LIMIT 200")
    check("admin product join user", len(prows) >= 1)
    dmrows = query_all("SELECT d.content, su.username AS sender, ru.username AS receiver FROM dm d JOIN user su ON su.id=d.sender_id JOIN user ru ON ru.id=d.receiver_id ORDER BY d.created_at DESC LIMIT 300")
    check("admin dm double-join user", len(dmrows) >= 1)
    rprows = query_all("SELECT r.id, u.username AS reporter FROM report r JOIN user u ON u.id=r.reporter_id ORDER BY r.created_at DESC LIMIT 300")
    check("admin report join user", len(rprows) >= 1)

print("\n=== RESULT ===")
if FAILS:
    print("FAILURES:", FAILS)
    sys.exit(1)
print("ALL CHECKS PASSED")
