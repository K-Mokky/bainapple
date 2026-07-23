"""Landing / index routes."""
from flask import Blueprint, g, redirect, render_template, url_for

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    if g.get("user") is not None:
        return redirect(url_for("main.dashboard"))
    return render_template("index.html")


@bp.route("/dashboard")
def dashboard():
    # Public dashboard placeholder; product listing is added by the products
    # blueprint. Kept here so the app has a coherent landing after login.
    return render_template("dashboard.html")
