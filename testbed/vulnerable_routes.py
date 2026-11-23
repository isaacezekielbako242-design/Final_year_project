"""DELIBERATELY VULNERABLE routes of the ShopLab testbed.

!!! FOR LOCAL, AUTHORISED, EDUCATIONAL USE ONLY - NEVER DEPLOY THIS CODE !!!

Every deliberate weakness is marked with its ground-truth identifier
(see evaluation/ground_truth.json):

    VULN-01  SQL injection         /search          parameter q
    VULN-02  SQL injection         /product         parameter id
    VULN-03  Reflected XSS         /search          parameter q
    VULN-04  Reflected XSS         /cart            parameter msg (cart status message)
    VULN-05  CSRF                  /profile/update  (no anti-CSRF token)
    VULN-06  CSRF                  /checkout        (order placement, no token)
    VULN-07  Broken access control /order           parameter id (no ownership check)
    VULN-08  Broken access control /profile/view    parameter user_id (no ownership check)
    VULN-09  Missing security headers               (no CSP / X-Content-Type-Options / X-Frame-Options)
    VULN-10  Insecure session cookie                (no HttpOnly, no SameSite)  -> see app.py
    VULN-11  Verbose error messages                 (stack traces shown to users)

Note: sqlite3's ``execute`` runs only ONE statement, so the injectable
queries cannot be used for stacked (destructive) statements.
"""

import platform
import sys
import traceback

from flask import redirect, render_template, request, url_for
from markupsafe import Markup
from werkzeug.exceptions import HTTPException

from . import models
from .security import current_user_id, login_required

# Endpoints for which the CSRF check is skipped (VULN-05, VULN-06).
CSRF_EXEMPT_ENDPOINTS = {"profile_update", "checkout"}


def register_vulnerable_routes(app):
    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        # VULN-01: user input concatenated directly into the SQL statement.
        sql = (
            "SELECT * FROM products WHERE name LIKE '%" + q + "%' "
            "OR description LIKE '%" + q + "%' ORDER BY product_id"
        )
        results = models.get_db().execute(sql).fetchall()
        # VULN-03: the search term is marked as "safe" HTML, so Jinja2 does
        # not escape it -> reflected XSS.
        return render_template("search.html", query=Markup(q), results=results)

    @app.route("/product")
    def product_detail():
        product_id = request.args.get("id", "")
        # VULN-02: numeric parameter concatenated into SQL without validation.
        sql = "SELECT * FROM products WHERE product_id = " + product_id
        product = models.get_db().execute(sql).fetchone()
        if product is None:
            return render_template("not_found.html", what="Product"), 404
        return render_template("product.html", product=product)

    @app.route("/cart")
    @login_required
    def cart():
        # VULN-04: the cart status message comes from the URL and is rendered unescaped.
        msg = Markup(request.args.get("msg", ""))
        items = models.get_cart(current_user_id())
        total = round(sum(i["price"] * i["quantity"] for i in items), 2)
        return render_template("cart.html", items=items, total=total, msg=msg)

    @app.route("/checkout", methods=["GET", "POST"])
    @login_required
    def checkout():
        # VULN-06: listed in CSRF_EXEMPT_ENDPOINTS, so no token is required here.
        if request.method == "POST":
            order_id = models.create_order_from_cart(current_user_id())
            if order_id is None:
                return redirect(url_for("cart", msg="Your cart is empty."))
            return redirect(url_for("order_detail", id=order_id))
        items = models.get_cart(current_user_id())
        total = round(sum(i["price"] * i["quantity"] for i in items), 2)
        return render_template("checkout.html", items=items, total=total,
                               user=models.get_user_by_id(current_user_id()))

    @app.route("/order")
    @login_required
    def order_detail():
        order_id = int(request.args.get("id", ""))  # ValueError -> verbose error page (VULN-11)
        order = models.get_order(order_id)
        if order is None:
            return render_template("not_found.html", what="Order"), 404
        # VULN-07: no check that order["user_id"] == current_user_id().
        return render_template("order.html", order=order, items=models.get_order_items(order_id))

    @app.route("/profile/view")
    @login_required
    def profile_view():
        user_id = int(request.args.get("user_id", current_user_id()))
        user = models.get_user_by_id(user_id)
        if user is None:
            return render_template("not_found.html", what="User"), 404
        # VULN-08: any logged-in user can view any other customer's profile.
        return render_template("profile_view.html", user=user)

    @app.route("/profile/update", methods=["POST"])
    @login_required
    def profile_update():
        # VULN-05: listed in CSRF_EXEMPT_ENDPOINTS, so no token is required here.
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        if "@" not in email:
            return redirect(url_for("profile", msg="Please enter a valid email address."))
        models.update_user_profile(current_user_id(), email, address)
        return redirect(url_for("profile", msg="Profile updated."))

    # VULN-11: unhandled exceptions are shown to the user with a full stack trace.
    @app.errorhandler(Exception)
    def verbose_error(exc):
        if isinstance(exc, HTTPException):
            return exc
        details = {
            "exception": f"{type(exc).__module__}.{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
            "python": sys.version,
            "platform": platform.platform(),
            "path": request.full_path,
        }
        return render_template("error_verbose.html", details=details), 500

    # VULN-09: deliberately NO after_request hook adding security headers.
