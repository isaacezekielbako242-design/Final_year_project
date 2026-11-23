"""PATCHED (control) routes of the ShopLab testbed.

Same URLs, parameters, forms and behaviour as ``vulnerable_routes.py`` but
with every documented weakness corrected:

    VULN-01/02  parameterised SQL queries + integer validation
    VULN-03/04  Jinja2 auto-escaping (no Markup() around user input)
    VULN-05/06  CSRF token required (CSRF_EXEMPT_ENDPOINTS is empty)
    VULN-07/08  ownership checks on orders and profiles
    VULN-09     security headers added by an after_request hook
    VULN-10     HttpOnly + SameSite session cookie (see app.py)
    VULN-11     generic error pages, details logged server-side only
"""

from flask import abort, redirect, render_template, request, url_for
from werkzeug.exceptions import HTTPException

from . import models
from .security import apply_security_headers, current_user_id, login_required

CSRF_EXEMPT_ENDPOINTS = set()


def register_patched_routes(app):
    @app.route("/search")
    def search():
        q = request.args.get("q", "")
        results = models.search_products(q)  # parameterised query
        return render_template("search.html", query=q, results=results)  # auto-escaped

    @app.route("/product")
    def product_detail():
        product_id = request.args.get("id", type=int)  # non-integers become None
        product = models.get_product(product_id) if product_id is not None else None
        if product is None:
            return render_template("not_found.html", what="Product"), 404
        return render_template("product.html", product=product)

    @app.route("/cart")
    @login_required
    def cart():
        msg = request.args.get("msg", "")  # plain string -> escaped by Jinja2
        items = models.get_cart(current_user_id())
        total = round(sum(i["price"] * i["quantity"] for i in items), 2)
        return render_template("cart.html", items=items, total=total, msg=msg)

    @app.route("/checkout", methods=["GET", "POST"])
    @login_required
    def checkout():
        # CSRF token validated by the global before_request hook.
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
        order_id = request.args.get("id", type=int)
        order = models.get_order(order_id) if order_id is not None else None
        # Ownership check: respond with 404 so other users' order IDs are not disclosed.
        if order is None or order["user_id"] != current_user_id():
            return render_template("not_found.html", what="Order"), 404
        return render_template("order.html", order=order, items=models.get_order_items(order_id))

    @app.route("/profile/view")
    @login_required
    def profile_view():
        user_id = request.args.get("user_id", default=current_user_id(), type=int)
        if user_id != current_user_id():  # ownership check
            abort(403)
        return render_template("profile_view.html", user=models.get_user_by_id(user_id))

    @app.route("/profile/update", methods=["POST"])
    @login_required
    def profile_update():
        email = request.form.get("email", "").strip()
        address = request.form.get("address", "").strip()
        if "@" not in email:
            return redirect(url_for("profile", msg="Please enter a valid email address."))
        models.update_user_profile(current_user_id(), email, address)
        return redirect(url_for("profile", msg="Profile updated."))

    @app.errorhandler(Exception)
    def generic_error(exc):
        if isinstance(exc, HTTPException):
            code = exc.code or 500
            return render_template("error_generic.html", code=code), code
        app.logger.exception("Unhandled error")  # details stay in the server log
        return render_template("error_generic.html", code=500), 500

    app.after_request(apply_security_headers)
