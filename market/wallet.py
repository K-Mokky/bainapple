"""Bank account management (require.txt §6).

Each user stores exactly one bank account (bank name / account number /
account holder). The seller sends this account into a 1:1 chat with a button
(see chat.py ``send_account``); the buyer clicks the received message to copy
the details to the clipboard and wires the money from an external banking app.

Security controls:
- All routes require authentication.
- Every field is validated server-side (length / character set).
- The account is only ever sent to a chat by its owner, read from the DB on
  the server (client cannot spoof another user's account into the button).
"""
from flask import (
    Blueprint,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from .db import execute, query_one
from .security import login_required
from .validators import (
    ValidationError,
    validate_account_holder,
    validate_account_number,
    validate_bank_name,
)

bp = Blueprint("wallet", __name__)


@bp.route("/wallet")
@login_required
def wallet():
    account = query_one(
        "SELECT bank_name, account_number, account_holder FROM user WHERE id = ?",
        (g.user["id"],),
    )
    return render_template("wallet.html", account=account)


@bp.route("/wallet/account", methods=["POST"])
@login_required
def save_account():
    try:
        bank_name = validate_bank_name(request.form.get("bank_name"))
        account_number = validate_account_number(request.form.get("account_number"))
        account_holder = validate_account_holder(request.form.get("account_holder"))
    except ValidationError as exc:
        flash(str(exc))
        return redirect(url_for("wallet.wallet"))
    execute(
        "UPDATE user SET bank_name = ?, account_number = ?, account_holder = ?"
        " WHERE id = ?",
        (bank_name, account_number, account_holder, g.user["id"]),
    )
    flash("계좌 정보가 저장되었습니다.")
    return redirect(url_for("wallet.wallet"))
