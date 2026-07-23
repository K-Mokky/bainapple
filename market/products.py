"""Product management, search and favorites.

Security controls:
- All mutating routes require authentication; edit/delete/status require
  ownership (or admin).
- Price is validated as a bounded non-negative integer.
- Image uploads are validated by extension, stored under a generated random
  filename (never trusting the client filename), and bounded by
  MAX_CONTENT_LENGTH.
- Search uses parameterized LIKE (no string concatenation into SQL); the
  ORDER BY clause comes from a server-side whitelist, never user input.
- Blocked products are hidden from public listings/detail.

Functional requirements (require.txt §3, §7):
- The listing is a filterable card grid (photo/name/price/time); the filter
  panel narrows by sale status and by a whitelisted category.
- Search needs a query of at least 2 characters and matches product titles.
- Sorting: latest / price asc / price desc / most favorited.
- A "selling only" filter hides sold items.
"""
import os

from datetime import datetime, timezone
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .db import execute, new_id, query_all, query_one
from .notifications import notify
from .security import login_required
from .validators import (
    ValidationError,
    validate_category,
    validate_description,
    validate_price,
    validate_title,
)

bp = Blueprint("products", __name__)

# Whitelisted ORDER BY fragments — the sort key from the query string is only
# ever used to look up this dict, never interpolated into SQL.
SORTS = {
    "latest": "p.created_at DESC",
    "price_asc": "p.price ASC, p.created_at DESC",
    "price_desc": "p.price DESC, p.created_at DESC",
    "likes": "fav_count DESC, p.created_at DESC",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ext_ok(filename: str) -> bool:
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in current_app.config["ALLOWED_IMAGE_EXTENSIONS"]
    )


def _sniff_image(head: bytes):
    """Return an image kind from magic bytes, or None. Portable (no imghdr)."""
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def _save_image(file_storage):
    """Validate and persist an uploaded image. Return stored filename or None."""
    if file_storage is None or not file_storage.filename:
        return None
    if not _ext_ok(file_storage.filename):
        raise ValidationError("허용되지 않는 이미지 형식입니다.")
    # Verify the bytes really look like an image (defense against a faked extension).
    head = file_storage.stream.read(512)
    file_storage.stream.seek(0)
    if _sniff_image(head) is None:
        raise ValidationError("이미지 파일이 아닙니다.")
    # Extension is taken from the already-validated (allowed) client name; the
    # stored name is fully server-generated (uuid), so no client string reaches
    # the filesystem path.
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    stored = f"{new_id()}.{ext}"
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], stored)
    file_storage.save(path)
    return stored


def _owned_product_or_403(product_id):
    product = query_one("SELECT * FROM product WHERE id = ?", (product_id,))
    if product is None:
        abort(404)
    if product["seller_id"] != g.user["id"] and not g.user["is_admin"]:
        abort(403)
    return product


@bp.route("/products")
def list_products():
    q = (request.args.get("q") or "").strip()
    sort = request.args.get("sort", "latest")
    if sort not in SORTS:
        sort = "latest"
    selling_only = request.args.get("selling") == "1"
    categories = current_app.config["PRODUCT_CATEGORIES"]
    category = (request.args.get("category") or "").strip()
    if category not in categories:
        category = ""

    if q and len(q) < current_app.config["SEARCH_MIN_LENGTH"]:
        flash(f"검색어는 {current_app.config['SEARCH_MIN_LENGTH']}자 이상 입력해주세요.")
        q = ""

    where = ["p.status = 'active'"]
    params = []
    if q:
        where.append("p.title LIKE ?")
        params.append(f"%{q}%")
    if selling_only:
        where.append("p.sale_status = 'selling'")
    if category:
        where.append("p.category = ?")
        params.append(category)

    products = query_all(
        "SELECT p.id, p.title, p.price, p.image_path, p.category, p.sale_status,"
        "       p.created_at, COUNT(f.product_id) AS fav_count"
        " FROM product p LEFT JOIN favorite f ON f.product_id = p.id"
        f" WHERE {' AND '.join(where)}"
        " GROUP BY p.id"
        f" ORDER BY {SORTS[sort]} LIMIT 200",
        tuple(params),
    )
    return render_template(
        "products.html",
        products=products,
        q=q,
        sort=sort,
        selling_only=selling_only,
        category=category,
        categories=categories,
    )


@bp.route("/product/new", methods=["GET", "POST"])
@login_required
def new_product():
    categories = current_app.config["PRODUCT_CATEGORIES"]
    if request.method == "POST":
        try:
            title = validate_title(request.form.get("title"))
            description = validate_description(request.form.get("description"))
            price = validate_price(request.form.get("price"))
            category = validate_category(request.form.get("category"))
            image = _save_image(request.files.get("image"))
        except ValidationError as exc:
            flash(str(exc))
            return render_template("new_product.html", categories=categories)
        pid = new_id()
        execute(
            "INSERT INTO product (id, title, description, price, seller_id, image_path, status, sale_status, category, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, 'active', 'selling', ?, ?)",
            (pid, title, description, price, g.user["id"], image, category, _now()),
        )
        flash("상품이 등록되었습니다.")
        return redirect(url_for("products.view_product", product_id=pid))
    return render_template("new_product.html", categories=categories)


@bp.route("/product/<product_id>")
def view_product(product_id):
    product = query_one("SELECT * FROM product WHERE id = ?", (product_id,))
    if product is None:
        abort(404)
    # Blocked products are only visible to the owner or an admin.
    if product["status"] != "active":
        user = g.get("user")
        if user is None or (user["id"] != product["seller_id"] and not user["is_admin"]):
            abort(404)
    seller = query_one(
        "SELECT id, username FROM user WHERE id = ?", (product["seller_id"],)
    )
    fav_count = query_one(
        "SELECT COUNT(*) AS c FROM favorite WHERE product_id = ?", (product_id,)
    )["c"]
    faved = False
    if g.get("user") is not None:
        faved = (
            query_one(
                "SELECT 1 FROM favorite WHERE user_id = ? AND product_id = ?",
                (g.user["id"], product_id),
            )
            is not None
        )
    return render_template(
        "view_product.html",
        product=product,
        seller=seller,
        fav_count=fav_count,
        faved=faved,
    )


@bp.route("/product/<product_id>/favorite", methods=["POST"])
@login_required
def toggle_favorite(product_id):
    product = query_one(
        "SELECT id, title, seller_id, status FROM product WHERE id = ?", (product_id,)
    )
    if product is None or product["status"] != "active":
        abort(404)
    if product["seller_id"] == g.user["id"]:
        flash("자신의 상품은 찜할 수 없습니다.")
        return redirect(url_for("products.view_product", product_id=product_id))
    existing = query_one(
        "SELECT 1 FROM favorite WHERE user_id = ? AND product_id = ?",
        (g.user["id"], product_id),
    )
    if existing is None:
        execute(
            "INSERT INTO favorite (user_id, product_id, created_at) VALUES (?, ?, ?)",
            (g.user["id"], product_id, _now()),
        )
        flash("찜 목록에 추가되었습니다.")
        notify(
            product["seller_id"],
            "favorite",
            g.user,
            f"{g.user['username']}님이 '{product['title']}' 상품을 찜했습니다.",
            product_id=product_id,
        )
    else:
        execute(
            "DELETE FROM favorite WHERE user_id = ? AND product_id = ?",
            (g.user["id"], product_id),
        )
        flash("찜을 해제했습니다.")
    return redirect(url_for("products.view_product", product_id=product_id))


@bp.route("/product/<product_id>/sale-status", methods=["POST"])
@login_required
def toggle_sale_status(product_id):
    product = _owned_product_or_403(product_id)
    new_status = "sold" if product["sale_status"] == "selling" else "selling"
    execute(
        "UPDATE product SET sale_status = ? WHERE id = ?", (new_status, product_id)
    )
    flash("판매 완료 처리되었습니다." if new_status == "sold" else "판매중으로 변경되었습니다.")
    return redirect(url_for("products.view_product", product_id=product_id))


@bp.route("/product/<product_id>/edit", methods=["GET", "POST"])
@login_required
def edit_product(product_id):
    product = _owned_product_or_403(product_id)
    categories = current_app.config["PRODUCT_CATEGORIES"]
    if request.method == "POST":
        try:
            title = validate_title(request.form.get("title"))
            description = validate_description(request.form.get("description"))
            price = validate_price(request.form.get("price"))
            category = validate_category(request.form.get("category"))
            new_image = _save_image(request.files.get("image"))
        except ValidationError as exc:
            flash(str(exc))
            return render_template(
                "edit_product.html", product=product, categories=categories
            )
        image_path = new_image or product["image_path"]
        execute(
            "UPDATE product SET title = ?, description = ?, price = ?, category = ?, image_path = ? WHERE id = ?",
            (title, description, price, category, image_path, product_id),
        )
        flash("상품이 수정되었습니다.")
        return redirect(url_for("products.view_product", product_id=product_id))
    return render_template("edit_product.html", product=product, categories=categories)


@bp.route("/product/<product_id>/delete", methods=["POST"])
@login_required
def delete_product(product_id):
    _owned_product_or_403(product_id)
    execute("DELETE FROM product WHERE id = ?", (product_id,))
    flash("상품이 삭제되었습니다.")
    return redirect(url_for("products.my_products"))


@bp.route("/products/mine")
@login_required
def my_products():
    products = query_all(
        "SELECT id, title, price, status, sale_status, image_path FROM product"
        " WHERE seller_id = ? ORDER BY created_at DESC",
        (g.user["id"],),
    )
    return render_template("my_products.html", products=products)
