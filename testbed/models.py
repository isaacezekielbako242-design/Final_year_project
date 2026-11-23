"""Data-access functions for the ShopLab testbed.

Every function in this module uses *parameterised* SQL queries and is shared
by both testbed versions. The deliberately vulnerable SQL lives ONLY in
``vulnerable_routes.py`` so that the flaws are isolated and easy to find.
"""

import sqlite3
from datetime import datetime

from flask import current_app, g

from .database import get_connection


# ---------------------------------------------------------------------------
# Connection handling (one connection per request)
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = get_connection(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def get_user_by_id(user_id):
    return get_db().execute(
        "SELECT user_id, username, email, address FROM users WHERE user_id = ?", (user_id,)
    ).fetchone()


def get_user_with_hash(username):
    return get_db().execute(
        "SELECT user_id, username, password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()


def create_user(username, password_hash, email, address):
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, email, address) VALUES (?, ?, ?, ?)",
            (username, password_hash, email, address),
        )
        db.commit()
        return cur.lastrowid
    except sqlite3.IntegrityError:
        return None


def update_user_profile(user_id, email, address):
    db = get_db()
    db.execute("UPDATE users SET email = ?, address = ? WHERE user_id = ?", (email, address, user_id))
    db.commit()


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------
def list_products(category=None):
    if category:
        return get_db().execute(
            "SELECT * FROM products WHERE category = ? ORDER BY product_id", (category,)
        ).fetchall()
    return get_db().execute("SELECT * FROM products ORDER BY product_id").fetchall()


def list_categories():
    rows = get_db().execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
    return [r["category"] for r in rows]


def get_product(product_id):
    return get_db().execute("SELECT * FROM products WHERE product_id = ?", (product_id,)).fetchone()


def search_products(term):
    like = f"%{term}%"
    return get_db().execute(
        "SELECT * FROM products WHERE name LIKE ? OR description LIKE ? ORDER BY product_id",
        (like, like),
    ).fetchall()


# ---------------------------------------------------------------------------
# Cart
# ---------------------------------------------------------------------------
def get_cart(user_id):
    return get_db().execute(
        "SELECT c.cart_item_id, c.quantity, p.product_id, p.name, p.price "
        "FROM cart_items c JOIN products p ON p.product_id = c.product_id "
        "WHERE c.user_id = ? ORDER BY c.cart_item_id",
        (user_id,),
    ).fetchall()


def add_to_cart(user_id, product_id, quantity):
    db = get_db()
    existing = db.execute(
        "SELECT cart_item_id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?",
        (user_id, product_id),
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE cart_items SET quantity = ? WHERE cart_item_id = ?",
            (existing["quantity"] + quantity, existing["cart_item_id"]),
        )
    else:
        db.execute(
            "INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)",
            (user_id, product_id, quantity),
        )
    db.commit()


def update_cart_item(user_id, cart_item_id, quantity):
    """Set the quantity of a cart line; quantity 0 removes it. Scoped to the owner."""
    db = get_db()
    if quantity <= 0:
        db.execute("DELETE FROM cart_items WHERE cart_item_id = ? AND user_id = ?", (cart_item_id, user_id))
    else:
        db.execute(
            "UPDATE cart_items SET quantity = ? WHERE cart_item_id = ? AND user_id = ?",
            (quantity, cart_item_id, user_id),
        )
    db.commit()


# ---------------------------------------------------------------------------
# Orders
# ---------------------------------------------------------------------------
def create_order_from_cart(user_id):
    """Convert the user's cart into an order. Returns the new order_id or None if the cart is empty."""
    db = get_db()
    items = get_cart(user_id)
    if not items:
        return None
    total = round(sum(i["price"] * i["quantity"] for i in items), 2)
    cur = db.execute(
        "INSERT INTO orders (user_id, total_amount, status, order_date) VALUES (?, ?, 'Pending', ?)",
        (user_id, total, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
    )
    order_id = cur.lastrowid
    for item in items:
        db.execute(
            "INSERT INTO order_items (order_id, product_id, quantity, unit_price) VALUES (?, ?, ?, ?)",
            (order_id, item["product_id"], item["quantity"], item["price"]),
        )
        db.execute(
            "UPDATE products SET stock = MAX(stock - ?, 0) WHERE product_id = ?",
            (item["quantity"], item["product_id"]),
        )
    db.execute("DELETE FROM cart_items WHERE user_id = ?", (user_id,))
    db.commit()
    return order_id


def list_orders_for_user(user_id):
    return get_db().execute(
        "SELECT * FROM orders WHERE user_id = ? ORDER BY order_id DESC", (user_id,)
    ).fetchall()


def get_order(order_id):
    """Fetch an order WITHOUT any ownership filtering (callers must enforce ownership)."""
    return get_db().execute(
        "SELECT o.*, u.username, u.email, u.address FROM orders o "
        "JOIN users u ON u.user_id = o.user_id WHERE o.order_id = ?",
        (order_id,),
    ).fetchone()


def get_order_items(order_id):
    return get_db().execute(
        "SELECT oi.quantity, oi.unit_price, p.name FROM order_items oi "
        "JOIN products p ON p.product_id = oi.product_id WHERE oi.order_id = ?",
        (order_id,),
    ).fetchall()
