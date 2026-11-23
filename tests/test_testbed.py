"""The vulnerable testbed exposes the documented cases; the patched one corrects them."""

import pytest

from tests.conftest import ALICE, BOB, login_test_client


@pytest.fixture
def vuln(vuln_client):
    login_test_client(vuln_client, *ALICE)
    return vuln_client


@pytest.fixture
def patched(patched_client):
    login_test_client(patched_client, *ALICE)
    return patched_client


def test_core_shop_functions_work(patched):
    assert b"Wireless Mouse" in patched.get("/products").data
    assert b"Mechanical Keyboard" in patched.get("/search?q=keyboard").data
    assert patched.get("/product?id=1").status_code == 200
    page = patched.get("/product?id=1").get_data(as_text=True)
    import re
    token = re.search(r'name="csrf_token" value="(\w+)"', page).group(1)
    r = patched.post("/cart/add", data={"product_id": 1, "quantity": 2, "csrf_token": token}, follow_redirects=True)
    assert b"Added 2 x Wireless Mouse" in r.data
    r = patched.post("/checkout", data={"csrf_token": token, "payment_method": "cod"}, follow_redirects=True)
    assert b"Order #" in r.data and b"Pending" in r.data
    assert b"Order history" in patched.get("/orders").data


def test_registration_and_password_hashing(patched_client):
    import re
    page = patched_client.get("/register").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="(\w+)"', page).group(1)
    r = patched_client.post("/register", data={"username": "carol", "password": "carol-pass-789",
                                                "email": "carol@shoplab.test", "address": "1 Fake Rd",
                                                "csrf_token": token}, follow_redirects=True)
    assert b"Account created" in r.data
    assert login_test_client(patched_client, "carol", "carol-pass-789").status_code == 302
    with patched_client.application.app_context():
        from testbed.models import get_db
        hashes = [r[0] for r in get_db().execute("SELECT password_hash FROM users")]
    assert all(h.startswith("pbkdf2:sha256") for h in hashes)


# --- SQL injection (VULN-01, VULN-02) ---
def test_sqli(vuln, patched):
    assert b"sqlite3.OperationalError" in vuln.get("/search?q=')").data
    assert vuln.get("/product?id=1 AND 1=1").status_code == 200
    assert vuln.get("/product?id=1 AND 1=2").status_code == 404
    assert b"OperationalError" not in patched.get("/search?q=')").data
    assert patched.get("/product?id=1 AND 1=1").status_code == 404


# --- Reflected XSS (VULN-03, VULN-04) ---
def test_xss(vuln, patched):
    assert b"<i>x</i>" in vuln.get("/search?q=<i>x</i>").data
    assert b"<i>x</i>" in vuln.get("/cart?msg=<i>x</i>").data
    assert b"&lt;i&gt;x&lt;/i&gt;" in patched.get("/search?q=<i>x</i>").data
    assert b"<i>x</i>" not in patched.get("/cart?msg=<i>x</i>").data


# --- CSRF (VULN-05, VULN-06) ---
def test_csrf(vuln, patched):
    assert b"csrf_token" not in vuln.get("/profile").data
    assert vuln.post("/profile/update", data={"email": "alice@shoplab.test", "address": "x"}).status_code == 302
    assert vuln.post("/checkout", data={}).status_code == 302
    assert patched.post("/profile/update", data={"email": "alice@shoplab.test", "address": "x"}).status_code == 400
    assert patched.post("/checkout", data={}).status_code == 400


# --- Broken access control (VULN-07, VULN-08); order 3 and user 2 belong to bob ---
def test_access_control(vuln, patched):
    assert b"bob" in vuln.get("/order?id=3").data
    assert b"bob@shoplab.test" in vuln.get("/profile/view?user_id=2").data
    assert patched.get("/order?id=3").status_code == 404
    assert patched.get("/profile/view?user_id=2").status_code == 403
    assert patched.get("/order?id=1").status_code == 200  # own order still works


# --- Headers, cookies and errors (VULN-09, VULN-10, VULN-11) ---
def test_headers(vuln_client, patched_client):
    v, p = vuln_client.get("/"), patched_client.get("/")
    for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert h not in v.headers and h in p.headers


def test_session_cookie_attributes(vuln_client, patched_client):
    v = login_test_client(vuln_client, *BOB).headers["Set-Cookie"]
    p = login_test_client(patched_client, *BOB).headers["Set-Cookie"]
    assert "HttpOnly" not in v and "SameSite" not in v
    assert "HttpOnly" in p and "SameSite=Lax" in p


def test_error_messages(vuln, patched):
    v, p = vuln.get("/product?id=x'"), patched.get("/order?id=abc")
    assert v.status_code == 500 and b"Traceback (most recent call last)" in v.data
    assert b"Traceback" not in p.data
    r = vuln.get("/order?id=abc")
    assert r.status_code == 500 and b"ValueError" in r.data
