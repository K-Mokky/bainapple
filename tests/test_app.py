"""End-to-end tests for functional requirements and security controls.

Mapped to secure_coding_checklist.csv items where relevant.
"""
import base64
import io

from market.db import query_one

# 1x1 transparent PNG
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def _uid(app, username):
    with app.app_context():
        return query_one("SELECT id FROM user WHERE username=?", (username,))["id"]


def _add_product(client, title="Bike", desc="nice", price="1000"):
    return client.post(
        "/product/new",
        data={"title": title, "description": desc, "price": price,
              "image": (io.BytesIO(PNG), "p.png")},
        content_type="multipart/form-data", follow_redirects=True,
    )


# --------------------------------------------------------------- headers
def test_security_headers(client):
    r = client.get("/")
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_session_cookie_flags(app, helper):
    helper.user("cookieuser")
    # fetch a fresh Set-Cookie by logging in again
    c2 = app.test_client()
    r = c2.post("/login", data={"username": "cookieuser", "password": "Password1"})
    sc = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in sc
    assert "SameSite" in sc


# ------------------------------------------------------------------ csrf
def test_csrf_blocks_tokenless_post(app):
    # Toggle CSRF on for this test only; Flask-WTF checks the flag per request.
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        c = app.test_client()
        r = c.post("/register", data={"username": "eve", "password": "Password1", "confirm": "Password1"})
        assert r.status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


# -------------------------------------------------------------- register
def test_register_validation(client):
    # weak password (too short, no digit rule) rejected
    r = client.post("/register", data={"username": "weakpw", "password": "short", "confirm": "short"},
                    follow_redirects=True)
    assert "비밀번호는".encode() in r.data or "영문과 숫자".encode() in r.data
    # short username rejected
    r = client.post("/register", data={"username": "ab", "password": "Password1", "confirm": "Password1"},
                    follow_redirects=True)
    assert "사용자명은".encode() in r.data


def test_password_hashed_not_plaintext(app, helper):
    helper.register("hashuser")
    with app.app_context():
        row = query_one("SELECT password_hash FROM user WHERE username='hashuser'")
    assert row["password_hash"] != "Password1"
    assert row["password_hash"].startswith(("pbkdf2:", "scrypt:"))


def test_duplicate_username(app, helper):
    helper.register("dupuser")
    r = helper.register("dupuser").post(
        "/register", data={"username": "dupuser", "password": "Password1", "confirm": "Password1"},
        follow_redirects=True)
    assert "이미 존재".encode() in r.data


# ----------------------------------------------------------------- login
def test_login_wrong_password(app, helper):
    helper.register("loginuser")
    c = app.test_client()
    r = c.post("/login", data={"username": "loginuser", "password": "WrongPass9"}, follow_redirects=True)
    assert "올바르지 않".encode() in r.data


def test_dormant_cannot_login(app, helper):
    helper.register("dormantuser")
    with app.app_context():
        from market.db import execute
        execute("UPDATE user SET status='dormant' WHERE username='dormantuser'")
    c = app.test_client()
    r = c.post("/login", data={"username": "dormantuser", "password": "Password1"}, follow_redirects=True)
    assert "휴면 계정".encode() in r.data


def test_sql_injection_login_safe(app, helper):
    helper.register("realuser")
    c = app.test_client()
    r = c.post("/login", data={"username": "realuser' OR '1'='1", "password": "x' OR '1'='1"},
               follow_redirects=True)
    assert "올바르지 않".encode() in r.data  # not authenticated


def test_password_change_requires_current(app, helper):
    c = helper.user("pwuser")
    r = c.post("/profile/password",
               data={"current_password": "nope", "new_password": "NewPass123", "confirm_password": "NewPass123"},
               follow_redirects=True)
    assert "현재 비밀번호가 올바르지".encode() in r.data


# ------------------------------------------------------------------- xss
def test_bio_xss_escaped(app, helper):
    c = helper.user("xssuser")
    c.post("/profile/bio", data={"bio": "<script>alert(1)</script>"}, follow_redirects=True)
    r = c.get("/profile")
    assert b"<script>alert(1)</script>" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_product_description_xss_escaped(app, helper):
    c = helper.user("xssprod")
    _add_product(c, title="XSS", desc="<b>bold</b>", price="100")
    pid = query_one_id(app, "XSS")
    r = c.get(f"/product/{pid}")
    assert b"<b>bold</b>" not in r.data
    assert b"&lt;b&gt;bold&lt;/b&gt;" in r.data


def query_one_id(app, title):
    with app.app_context():
        return query_one("SELECT id FROM product WHERE title=?", (title,))["id"]


# -------------------------------------------------------------- products
def test_unauth_cannot_create_product(client):
    r = client.get("/product/new", follow_redirects=False)
    assert r.status_code in (301, 302)


def test_product_ownership_enforced(app, helper):
    owner = helper.user("owner1")
    other = helper.user("other1")
    _add_product(owner, title="Owned", price="500")
    pid = query_one_id(app, "Owned")
    assert other.get(f"/product/{pid}/edit").status_code == 403
    assert other.post(f"/product/{pid}/delete").status_code == 403


def test_fake_image_rejected(app, helper):
    c = helper.user("imguser")
    r = c.post("/product/new",
               data={"title": "Fake", "description": "d", "price": "1",
                     "image": (io.BytesIO(b"not an image"), "x.png")},
               content_type="multipart/form-data", follow_redirects=True)
    assert "이미지 파일이 아닙니다".encode() in r.data

def test_image_odd_filename_no_crash(app, helper):
    # A dotfile-style name (".png") must not raise; either accepted with a
    # server-generated name or cleanly rejected, never a 500.
    c = helper.user("imgodd")
    r = c.post("/product/new",
               data={"title": "Odd", "description": "d", "price": "1",
                     "image": (io.BytesIO(PNG), ".png")},
               content_type="multipart/form-data", follow_redirects=True)
    assert r.status_code == 200


def test_negative_price_rejected(app, helper):
    c = helper.user("priceuser")
    r = c.post("/product/new", data={"title": "Bad", "description": "d", "price": "-5"},
               follow_redirects=True)
    assert "가격은 0 이상".encode() in r.data


def test_blocked_product_hidden(app, helper):
    seller = helper.user("seller2")
    viewer = helper.user("viewer2")
    _add_product(seller, title="Hideme", price="10")
    pid = query_one_id(app, "Hideme")
    with app.app_context():
        from market.db import execute
        execute("UPDATE product SET status='blocked' WHERE id=?", (pid,))
    assert b"Hideme" not in viewer.get("/products").data
    assert viewer.get(f"/product/{pid}").status_code == 404


def test_search_title_match(app, helper):
    c = helper.user("searchuser")
    _add_product(c, title="RedShoes", desc="running", price="10")
    _add_product(c, title="BlueHat", desc="warm", price="20")
    assert b"RedShoes" in c.get("/products?q=Red").data
    assert b"BlueHat" not in c.get("/products?q=Red").data


def test_search_min_two_chars(app, helper):
    c = helper.user("minsearch")
    _add_product(c, title="MinTwoItem", price="10")
    r = c.get("/products?q=M", follow_redirects=True)
    assert "2자 이상".encode() in r.data
    # 1-char query is ignored -> full listing still shown
    assert b"MinTwoItem" in r.data


def test_search_sort_by_price(app, helper):
    c = helper.user("sortuser")
    _add_product(c, title="SortCheap", price="100")
    _add_product(c, title="SortPricey", price="900")
    asc = c.get("/products?q=Sort&sort=price_asc").data
    assert asc.index(b"SortCheap") < asc.index(b"SortPricey")
    desc = c.get("/products?q=Sort&sort=price_desc").data
    assert desc.index(b"SortPricey") < desc.index(b"SortCheap")


def test_search_selling_only_filter(app, helper):
    c = helper.user("sellfilter")
    _add_product(c, title="FilterSelling", price="10")
    _add_product(c, title="FilterSold", price="10")
    sold_pid = query_one_id(app, "FilterSold")
    c.post(f"/product/{sold_pid}/sale-status", follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT sale_status FROM product WHERE id=?", (sold_pid,))["sale_status"] == "sold"
    filtered = c.get("/products?q=Filter&selling=1").data
    assert b"FilterSelling" in filtered
    assert b"FilterSold" not in filtered
    unfiltered = c.get("/products?q=Filter").data
    assert b"FilterSold" in unfiltered


def test_category_filter(app, helper):
    c = helper.user("catuser")
    c.post("/product/new",
           data={"title": "CatPhone", "description": "d", "price": "10", "category": "디지털기기"},
           follow_redirects=True)
    c.post("/product/new",
           data={"title": "CatSofa", "description": "d", "price": "10", "category": "가구/인테리어"},
           follow_redirects=True)
    filtered = c.get("/products", query_string={"category": "디지털기기"}).data
    assert b"CatPhone" in filtered
    assert b"CatSofa" not in filtered
    # a value outside the whitelist is ignored -> unfiltered listing
    both = c.get("/products", query_string={"category": "nope"}).data
    assert b"CatPhone" in both and b"CatSofa" in both


def test_category_default_and_whitelist(app, helper):
    c = helper.user("catdefault")
    # omitted category falls back to the default bucket
    _add_product(c, title="CatDefault", price="10")
    with app.app_context():
        row = query_one("SELECT category FROM product WHERE title='CatDefault'")
    assert row["category"] == "기타"
    # non-whitelisted category rejected on create
    r = c.post("/product/new",
               data={"title": "CatBad", "description": "d", "price": "1", "category": "<script>"},
               follow_redirects=True)
    assert "올바르지 않은 카테고리".encode() in r.data


def test_favorite_toggle_and_sort(app, helper):
    seller = helper.user("favseller")
    _add_product(seller, title="FavPopular", price="10")
    _add_product(seller, title="FavIgnored", price="10")
    pid = query_one_id(app, "FavPopular")
    buyer = helper.user("favbuyer")
    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT COUNT(*) c FROM favorite WHERE product_id=?", (pid,))["c"] == 1
    listing = buyer.get("/products?q=Fav&sort=likes").data
    assert listing.index(b"FavPopular") < listing.index(b"FavIgnored")
    # own product cannot be favorited
    r = seller.post(f"/product/{pid}/favorite", follow_redirects=True)
    assert "자신의 상품".encode() in r.data
    # toggle off
    buyer.post(f"/product/{pid}/favorite", follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT COUNT(*) c FROM favorite WHERE product_id=?", (pid,))["c"] == 0


# ----------------------------------------------------- bank account (§6)
def test_account_save_and_validation(app, helper):
    c = helper.user("bankuser")
    r = c.post("/wallet/account",
               data={"bank_name": "국민은행", "account_number": "123-456-789012", "account_holder": "홍길동"},
               follow_redirects=True)
    assert "저장되었습니다".encode() in r.data
    with app.app_context():
        row = query_one("SELECT bank_name, account_number, account_holder FROM user WHERE username='bankuser'")
    assert row["account_number"] == "123-456-789012"
    # invalid account number rejected
    r = c.post("/wallet/account",
               data={"bank_name": "국민은행", "account_number": "abc<script>", "account_holder": "홍길동"},
               follow_redirects=True)
    assert "계좌번호는".encode() in r.data


# ------------------------------------------------------------ moderation
def test_report_dedupe_and_threshold(app, helper):
    seller = helper.user("modseller")
    _add_product(seller, title="Spammy", price="1")
    pid = query_one_id(app, "Spammy")
    r1 = helper.user("modrep1")
    r2 = helper.user("modrep2")
    r3 = helper.user("modrep3")
    r1.post("/report", data={"target_type": "product", "target_id": pid, "reason": "s"}, follow_redirects=True)
    dup = r1.post("/report", data={"target_type": "product", "target_id": pid, "reason": "s"}, follow_redirects=True)
    assert "이미 신고".encode() in dup.data
    r2.post("/report", data={"target_type": "product", "target_id": pid, "reason": "s"}, follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT status FROM product WHERE id=?", (pid,))["status"] == "active"
    r3.post("/report", data={"target_type": "product", "target_id": pid, "reason": "s"}, follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT status FROM product WHERE id=?", (pid,))["status"] == "blocked"


def test_cannot_report_self(app, helper):
    c = helper.user("selfreport")
    uid = _uid(app, "selfreport")
    r = c.post("/report", data={"target_type": "user", "target_id": uid, "reason": "x"}, follow_redirects=True)
    assert "자기 자신".encode() in r.data


# ----------------------------------------------------------------- admin
def test_admin_rbac(app, helper):
    normal = helper.user("normaluser")
    assert normal.get("/admin/", follow_redirects=False).status_code == 403
    admin = helper.admin()
    assert admin.get("/admin/").status_code == 200


def test_admin_requires_key_file(app, helper):
    # is_admin alone is NOT enough: without the key file the dashboard redirects
    # to the key gate (require.txt §8).
    admin = helper.login("admin", "Admin12345")
    r = admin.get("/admin/", follow_redirects=False)
    assert r.status_code in (301, 302)
    assert "/admin/key" in r.headers["Location"]
    # wrong key rejected
    import io as _io
    r = admin.post("/admin/key",
                   data={"key_file": (_io.BytesIO(b"not-the-key"), "fake.txt")},
                   content_type="multipart/form-data", follow_redirects=True)
    assert "올바르지 않".encode() in r.data
    assert admin.get("/admin/", follow_redirects=False).status_code in (301, 302)


def test_admin_chat_oversight(app, helper):
    a = helper.user("overseena")
    helper.user("overseenb")
    bid = _uid(app, "overseenb")
    from market import socketio as _socketio
    sa = _socketio.test_client(app, flask_test_client=a)
    sa.emit("join_dm", {"peer_id": bid})
    sa.emit("dm_message", {"peer_id": bid, "message": "dm-oversight-msg"})
    sa.disconnect()
    admin = helper.admin()
    assert b"dm-oversight-msg" in admin.get("/admin/dms").data


def test_admin_block_product(app, helper):
    seller = helper.user("adminseller")
    _add_product(seller, title="AdminBlock", price="1")
    pid = query_one_id(app, "AdminBlock")
    admin = helper.admin()
    admin.post(f"/admin/product/{pid}/block", follow_redirects=True)
    with app.app_context():
        assert query_one("SELECT status FROM product WHERE id=?", (pid,))["status"] == "blocked"

