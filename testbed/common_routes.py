"""Routes that are IDENTICAL in the vulnerable and patched versions.

Registration, login/logout, product listing, cart add/update and order
history contain no deliberate vulnerabilities. Routes that differ between
the versions live in ``vulnerable_routes.py`` and ``patched_routes.py``.
"""

from flask import flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import models
from .security import current_user_id, login_required


def register_common_routes(app):
    @app.route("/")
    def index():
        return render_template("index.html", products=models.list_products()[:6])

    @app.route("/products")
    def products():
        category = request.args.get("category") or None
        return render_template(
            "products.html",
            products=models.list_products(category),
            categories=models.list_categories(),
            selected=category,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            email = request.form.get("email", "").strip()
            address = request.form.get("address", "").strip()
            if len(username) < 3 or len(password) < 8 or "@" not in email:
                flash("Username (3+ chars), password (8+ chars) and a valid email are required.", "error")
            elif models.create_user(username, generate_password_hash(password, method="pbkdf2:sha256"),
                                    email, address) is None:
                flash("That username or email is already registered.", "error")
            else:
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            user = models.get_user_with_hash(request.form.get("username", "").strip())
            if user and check_password_hash(user["password_hash"], request.form.get("password", "")):
                session.clear()  # prevent session fixation
                session["user_id"] = user["user_id"]
                session["username"] = user["username"]
                return redirect(url_for("index"))
            flash("Invalid username or password.", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/cart/add", methods=["POST"])
    @login_required
    def cart_add():
        product_id = request.form.get("product_id", type=int)
        quantity = request.form.get("quantity", type=int)
        product = models.get_product(product_id) if product_id else None
        if not product or not quantity or quantity < 1 or quantity > 20:
            return redirect(url_for("cart", msg="Could not add item: invalid product or quantity."))
        models.add_to_cart(current_user_id(), product_id, quantity)
        return redirect(url_for("cart", msg=f"Added {quantity} x {product['name']} to your cart."))

    @app.route("/cart/update", methods=["POST"])
    @login_required
    def cart_update():
        cart_item_id = request.form.get("cart_item_id", type=int)
        quantity = request.form.get("quantity", type=int)
        if cart_item_id is None or quantity is None or quantity < 0 or quantity > 20:
            return redirect(url_for("cart", msg="Invalid cart update."))
        models.update_cart_item(current_user_id(), cart_item_id, quantity)
        return redirect(url_for("cart", msg="Cart updated."))

    @app.route("/orders")
    @login_required
    def orders():
        return render_template("orders.html", orders=models.list_orders_for_user(current_user_id()))

    @app.route("/profile")
    @login_required
    def profile():
        """Profile edit page (the form posts to the version-specific /profile/update)."""
        return render_template("profile_edit.html", user=models.get_user_by_id(current_user_id()),
                               msg=request.args.get("msg"))
