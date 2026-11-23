"""Security helpers shared by both testbed versions.

* ``login_required``  - redirects anonymous users to the login page.
* CSRF protection     - a per-session random token, validated on every POST
                        unless the endpoint is listed in
                        ``app.config['CSRF_EXEMPT_ENDPOINTS']``.
* ``csrf_field``      - template helper that renders the hidden token field.

In the VULNERABLE version the profile-update and checkout endpoints are put
on the exempt list (and their forms render no token) - test cases VULN-05 and
VULN-06. In the PATCHED version the exempt list is empty.
"""

import hmac
import secrets
from functools import wraps

from flask import abort, current_app, redirect, request, session, url_for
from markupsafe import Markup

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"


def current_user_id():
    return session.get("user_id")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user_id() is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def get_csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_hex(32)
        session[CSRF_SESSION_KEY] = token
    return token


def csrf_field(target_endpoint):
    """Render the hidden CSRF input for a form that posts to ``target_endpoint``."""
    if target_endpoint in current_app.config.get("CSRF_EXEMPT_ENDPOINTS", set()):
        return Markup("")  # Deliberately omitted in the vulnerable version.
    return Markup(f'<input type="hidden" name="{CSRF_FORM_FIELD}" value="{get_csrf_token()}">')


def csrf_protect():
    """``before_request`` hook validating the CSRF token on state-changing requests."""
    if request.method != "POST":
        return None
    if request.endpoint in current_app.config.get("CSRF_EXEMPT_ENDPOINTS", set()):
        return None
    expected = session.get(CSRF_SESSION_KEY, "")
    supplied = request.form.get(CSRF_FORM_FIELD, "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, description="CSRF token missing or invalid.")
    return None


def apply_security_headers(response):
    """``after_request`` hook used ONLY by the patched version."""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    return response
