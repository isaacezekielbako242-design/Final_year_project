"""Each detection module performs its intended checks.

Positive cases run against the vulnerable testbed; the same checks against the
patched testbed must report nothing.
"""

from scanner.csrf import request_accepted, token_fields
from scanner.models import BAC, CSRF, MISCONFIG, SQLI, XSS, Form, FormField
from scanner.security_misconfiguration import STACK_TRACE_RE, parse_set_cookie, redact_cookie
from scanner.sql_injection import find_db_error
from tests.conftest import findings_of, make_config


# ---- SQL injection -----------------------------------------------------------
def test_sqli_detected_in_search_and_product(vulnerable_scan):
    search = findings_of(vulnerable_scan, SQLI, "/search", "q")
    product = findings_of(vulnerable_scan, SQLI, "/product", "id")
    assert search and product
    for f in search + product:
        assert "error_based" in f["check"] and "boolean_based" in f["check"]
        assert "sqlite3.OperationalError" in f["evidence"]
        assert f["severity"] == "High"


def test_sqli_not_reported_for_parameterised_queries(vulnerable_scan, patched_scan):
    # /order and /profile/view use parameterised queries even in the vulnerable version.
    assert not findings_of(vulnerable_scan, SQLI, "/order")
    assert not findings_of(vulnerable_scan, SQLI, "/products")
    assert not findings_of(patched_scan, SQLI)


def test_db_error_signatures():
    assert find_db_error('sqlite3.OperationalError: near ")": syntax error')
    assert find_db_error("You have an error in your SQL syntax; check the manual")
    assert find_db_error("ValueError: invalid literal for int()") is None


# ---- XSS -------------------------------------------------------------------------
def test_reflected_xss_detected(vulnerable_scan):
    assert findings_of(vulnerable_scan, XSS, "/search", "q")
    cart = findings_of(vulnerable_scan, XSS, "/cart", "msg")
    assert cart and "UNENCODED" in cart[0]["evidence"]


def test_encoded_reflection_not_reported(patched_scan):
    assert not findings_of(patched_scan, XSS)


def test_xss_module_skips_unreflected_parameters(vulnerable_scan):
    assert not findings_of(vulnerable_scan, XSS, "/products", "category")


# ---- CSRF ------------------------------------------------------------------------
def test_csrf_detected_on_profile_update_and_checkout(vulnerable_scan):
    for path in ("/profile/update", "/checkout"):
        f = findings_of(vulnerable_scan, CSRF, path)
        assert f and f[0]["confidence"] == "Confirmed" and "ACCEPTED" in f[0]["evidence"]


def test_csrf_protected_forms_not_reported(vulnerable_scan, patched_scan):
    assert not findings_of(vulnerable_scan, CSRF, "/cart/add")  # token validated even in vulnerable version
    assert not findings_of(patched_scan, CSRF)


def test_csrf_helpers():
    form = Form("http://x/", "http://x/p", "POST",
                [FormField("csrf_token", "hidden", "abc"), FormField("email", "email", "a@b.c")])
    assert [f.name for f in token_fields(form)] == ["csrf_token"]
    assert request_accepted(None, None) is False


# ---- Broken access control ---------------------------------------------------------
def test_bac_detected_for_orders_and_profiles(vulnerable_scan):
    assert findings_of(vulnerable_scan, BAC, "/order", "id")
    assert findings_of(vulnerable_scan, BAC, "/profile/view", "user_id")


def test_bac_not_reported_when_ownership_enforced(patched_scan):
    assert not findings_of(patched_scan, BAC)


def test_bac_requires_two_accounts(vulnerable_server):
    from scanner.detection_engine import ScanEngine
    from tests.conftest import ALICE
    result = ScanEngine(make_config(vulnerable_server.url, users=(ALICE,), modules=["bac"])).run()
    assert not findings_of(result, BAC)
    assert any("two" in n for n in result["notes"])


# ---- Security misconfiguration --------------------------------------------------
def test_misconfigurations_detected(vulnerable_scan):
    checks = {f["check"] for f in findings_of(vulnerable_scan, MISCONFIG)}
    assert checks == {"missing_security_headers", "insecure_session_cookie", "verbose_errors"}
    headers = [f for f in vulnerable_scan["findings"] if f["check"] == "missing_security_headers"][0]
    for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert h in headers["parameter"]
    cookie = [f for f in vulnerable_scan["findings"] if f["check"] == "insecure_session_cookie"][0]
    assert "HttpOnly" in cookie["evidence"] and "SameSite" in cookie["evidence"]


def test_no_misconfigurations_in_patched(patched_scan):
    assert not findings_of(patched_scan, MISCONFIG)


def test_cookie_parsing_and_redaction():
    name, attrs = parse_set_cookie("session=abc.def; HttpOnly; Path=/; SameSite=Lax")
    assert name == "session" and attrs["httponly"] is True and attrs["samesite"] == "Lax"
    assert "abc" not in redact_cookie("session=abc.def; Path=/")


def test_stack_trace_signatures():
    assert STACK_TRACE_RE.search("Traceback (most recent call last):\n  File \"app.py\", line 3")
    assert not STACK_TRACE_RE.search("Something went wrong. Please try again later.")
