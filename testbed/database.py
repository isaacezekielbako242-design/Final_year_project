"""Database initialisation and seeding for the ShopLab testbed (SQLite).

Usage:
    python -m testbed.database                 # create/reset both databases
    python -m testbed.database --mode vulnerable
    python -m testbed.database --mode patched

Each testbed mode uses its own database file so that scans against one
version never affect the other.

Passwords are ALWAYS hashed (PBKDF2-SHA256 via Werkzeug), even in the
vulnerable version - the deliberate weaknesses are limited to the eleven
documented test cases.
"""

import argparse
import os
import sqlite3
from datetime import datetime

from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    address       TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS products (
    product_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL,
    category    TEXT    NOT NULL,
    price       REAL    NOT NULL CHECK (price >= 0),
    stock       INTEGER NOT NULL CHECK (stock >= 0)
);

CREATE TABLE IF NOT EXISTS cart_items (
    cart_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    product_id   INTEGER NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    quantity     INTEGER NOT NULL CHECK (quantity > 0),
    UNIQUE (user_id, product_id)
);

CREATE TABLE IF NOT EXISTS orders (
    order_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    total_amount REAL    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'Pending',
    order_date   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS order_items (
    order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id      INTEGER NOT NULL REFERENCES orders(order_id) ON DELETE CASCADE,
    product_id    INTEGER NOT NULL REFERENCES products(product_id),
    quantity      INTEGER NOT NULL CHECK (quantity > 0),
    unit_price    REAL    NOT NULL
);
"""

# ---------------------------------------------------------------------------
# Fictitious seed data
# ---------------------------------------------------------------------------
SAMPLE_PRODUCTS = [
    ("Wireless Mouse", "Ergonomic 2.4GHz wireless mouse with silent clicks.", "Electronics", 19.99, 120),
    ("Mechanical Keyboard", "Compact 87-key keyboard with blue switches.", "Electronics", 64.50, 45),
    ("USB-C Charger", "65W fast charger compatible with most laptops.", "Electronics", 29.00, 80),
    ("Noise Cancelling Headphones", "Over-ear headphones with 30-hour battery.", "Electronics", 129.99, 25),
    ("Cotton T-Shirt", "Soft unisex t-shirt made from organic cotton.", "Clothing", 12.00, 200),
    ("Running Shoes", "Lightweight running shoes with breathable mesh.", "Clothing", 74.95, 60),
    ("Denim Jacket", "Classic blue denim jacket, regular fit.", "Clothing", 55.00, 30),
    ("Ceramic Coffee Mug", "350ml mug, dishwasher safe.", "Home", 8.50, 150),
    ("Desk Lamp", "LED desk lamp with adjustable brightness.", "Home", 22.99, 70),
    ("Python Programming Book", "Beginner-friendly guide to Python 3.", "Books", 34.99, 40),
    ("Web Security Handbook", "Introduction to secure web development.", "Books", 41.00, 35),
    ("Water Bottle", "Insulated stainless-steel bottle, 750ml.", "Sports", 17.25, 90),
]

# Test accounts (fictitious). The passwords are documented in README.md.
TEST_USERS = [
    ("alice", "alice-pass-123", "alice@shoplab.test", "12 Example Street, Testville"),
    ("bob", "bob-pass-456", "bob@shoplab.test", "34 Sample Avenue, Mockton"),
]

# Orders per user: list of (status, date, [(product_id, quantity), ...])
TEST_ORDERS = {
    "alice": [
        ("Delivered", "2026-09-14 10:22:00", [(1, 1), (8, 2)]),
        ("Shipped", "2026-10-03 16:05:00", [(10, 1)]),
    ],
    "bob": [
        ("Pending", "2026-10-21 09:40:00", [(5, 3), (12, 1)]),
    ],
}


def db_path_for_mode(mode):
    """Return the SQLite file used by a testbed mode ('vulnerable' or 'patched')."""
    return os.path.join(INSTANCE_DIR, f"shoplab_{mode}.db")


def get_connection(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path, reset=True):
    """Create the schema and insert the sample products, users and orders."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if reset and os.path.exists(db_path):
        os.remove(db_path)

    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            _seed(conn)
        conn.commit()
    finally:
        conn.close()
    return db_path


def _seed(conn):
    conn.executemany(
        "INSERT INTO products (name, description, category, price, stock) VALUES (?, ?, ?, ?, ?)",
        SAMPLE_PRODUCTS,
    )
    user_ids = {}
    for username, password, email, address in TEST_USERS:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, email, address) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password, method="pbkdf2:sha256"), email, address),
        )
        user_ids[username] = cur.lastrowid

    for username, orders in TEST_ORDERS.items():
        for status, date, items in orders:
            total = 0.0
            priced = []
            for product_id, qty in items:
                price = conn.execute(
                    "SELECT price FROM products WHERE product_id = ?", (product_id,)
                ).fetchone()[0]
                total += price * qty
                priced.append((product_id, qty, price))
            cur = conn.execute(
                "INSERT INTO orders (user_id, total_amount, status, order_date) VALUES (?, ?, ?, ?)",
                (user_ids[username], round(total, 2), status, date),
            )
            for product_id, qty, price in priced:
                conn.execute(
                    "INSERT INTO order_items (order_id, product_id, quantity, unit_price) "
                    "VALUES (?, ?, ?, ?)",
                    (cur.lastrowid, product_id, qty, price),
                )


def main():
    parser = argparse.ArgumentParser(description="Initialise the ShopLab testbed database(s).")
    parser.add_argument("--mode", choices=["vulnerable", "patched", "both"], default="both")
    args = parser.parse_args()
    modes = ["vulnerable", "patched"] if args.mode == "both" else [args.mode]
    for mode in modes:
        path = init_db(db_path_for_mode(mode), reset=True)
        print(f"[{datetime.now():%H:%M:%S}] Initialised {mode} database: {path}")
    print("Test accounts: " + ", ".join(f"{u} / {p}" for u, p, _, _ in TEST_USERS))


if __name__ == "__main__":
    main()
