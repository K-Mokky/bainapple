"""Server-side input validation helpers.

These enforce length, character-set and format rules before any value is
persisted. Output escaping is handled by Jinja2 autoescaping in templates.
"""
import re

from .config import Config

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


class ValidationError(ValueError):
    pass


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not (Config.USERNAME_MIN <= len(username) <= Config.USERNAME_MAX):
        raise ValidationError(
            f"사용자명은 {Config.USERNAME_MIN}~{Config.USERNAME_MAX}자여야 합니다."
        )
    if not _USERNAME_RE.match(username):
        raise ValidationError("사용자명은 영문/숫자/밑줄(_)만 사용할 수 있습니다.")
    return username


def validate_password(password: str) -> str:
    password = password or ""
    if not (Config.PASSWORD_MIN <= len(password) <= Config.PASSWORD_MAX):
        raise ValidationError(
            f"비밀번호는 {Config.PASSWORD_MIN}~{Config.PASSWORD_MAX}자여야 합니다."
        )
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValidationError("비밀번호는 영문과 숫자를 모두 포함해야 합니다.")
    return password


def validate_bio(bio: str) -> str:
    bio = (bio or "").strip()
    if len(bio) > Config.BIO_MAX:
        raise ValidationError(f"소개글은 최대 {Config.BIO_MAX}자입니다.")
    return bio


def validate_title(title: str) -> str:
    title = (title or "").strip()
    if not (1 <= len(title) <= Config.PRODUCT_TITLE_MAX):
        raise ValidationError(
            f"상품명은 1~{Config.PRODUCT_TITLE_MAX}자여야 합니다."
        )
    return title


def validate_description(description: str) -> str:
    description = (description or "").strip()
    if not (1 <= len(description) <= Config.PRODUCT_DESC_MAX):
        raise ValidationError(
            f"상품 설명은 1~{Config.PRODUCT_DESC_MAX}자여야 합니다."
        )
    return description


def validate_price(price: str) -> int:
    price = (price or "").strip()
    if not re.fullmatch(r"\d{1,10}", price):
        raise ValidationError("가격은 0 이상의 정수여야 합니다.")
    value = int(price)
    if value > Config.PRODUCT_PRICE_MAX:
        raise ValidationError("가격이 허용 범위를 초과했습니다.")
    return value


def validate_category(category: str) -> str:
    """Whitelist check against the fixed category list.

    An omitted value falls back to the default bucket so pre-category
    clients keep working; anything else must match exactly.
    """
    category = (category or "").strip()
    if not category:
        return Config.PRODUCT_CATEGORY_DEFAULT
    if category not in Config.PRODUCT_CATEGORIES:
        raise ValidationError("올바르지 않은 카테고리입니다.")
    return category


_ACCOUNT_RE = re.compile(r"^[0-9][0-9-]{2,28}[0-9]$")


def validate_bank_name(bank_name: str) -> str:
    bank_name = (bank_name or "").strip()
    if not (1 <= len(bank_name) <= Config.BANK_NAME_MAX):
        raise ValidationError(f"은행명은 1~{Config.BANK_NAME_MAX}자여야 합니다.")
    return bank_name


def validate_account_number(account_number: str) -> str:
    account_number = (account_number or "").strip()
    if len(account_number) > Config.ACCOUNT_NUMBER_MAX or not _ACCOUNT_RE.match(
        account_number
    ):
        raise ValidationError("계좌번호는 숫자와 하이픈(-)으로 4~30자여야 합니다.")
    return account_number


def validate_account_holder(account_holder: str) -> str:
    account_holder = (account_holder or "").strip()
    if not (1 <= len(account_holder) <= Config.ACCOUNT_HOLDER_MAX):
        raise ValidationError(
            f"예금주는 1~{Config.ACCOUNT_HOLDER_MAX}자여야 합니다."
        )
    return account_holder


def validate_reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not (1 <= len(reason) <= Config.REASON_MAX):
        raise ValidationError(f"사유는 1~{Config.REASON_MAX}자여야 합니다.")
    return reason


def validate_message(content: str) -> str:
    content = (content or "").strip()
    if not (1 <= len(content) <= Config.CHAT_MAX_LENGTH):
        raise ValidationError("메시지 길이가 올바르지 않습니다.")
    return content
