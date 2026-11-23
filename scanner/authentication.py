"""Authentication and session management.

``SessionManager`` owns one anonymous HttpClient plus one authenticated
HttpClient per supplied test account (each with its own cookie jar), which is
what the broken-access-control module needs to compare two users.

Login is generic: the login page is located (supplied URL, a "login" link, or
common paths), the form containing a password field is parsed, hidden fields
such as CSRF tokens are preserved, and success is verified afterwards.
Passwords are held in memory only and are never logged or reported.
"""

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

from .html_utils import extract_links, parse_forms, soup_of
from .http_client import HttpClient, is_html

COMMON_LOGIN_PATHS = ["/login", "/signin", "/account/login", "/user/login", "/auth/login"]
LOGOUT_RE = re.compile(r"log\s*-?\s*out|sign\s*-?\s*out", re.I)
LOGIN_RE = re.compile(r"log\s*-?\s*in|sign\s*-?\s*in", re.I)
USERNAME_HINT = re.compile(r"user|login|email|mail|name|account", re.I)


class AuthenticationError(Exception):
    pass


@dataclass
class AuthSession:
    label: str
    username: str
    client: HttpClient
    authenticated: bool
    message: str
    user_id_hint: Optional[str] = None


def find_login_form(html, page_url, scope):
    for form in parse_forms(soup_of(html), page_url, scope):
        if form.has_password_field():
            return form
    return None


def discover_login_url(client, target_url):
    """Find the login page: a 'login' link on the start page, else common paths."""
    resp = client.get(target_url)
    if resp is not None and is_html(resp):
        if find_login_form(resp.text, resp.url, client.scope):
            return resp.url
        soup = soup_of(resp.text)
        for a in soup.find_all("a"):
            if LOGIN_RE.search(a.get_text(" ") or "") or LOGIN_RE.search(a.get("href") or ""):
                url = client.scope.normalise(a.get("href"), base=resp.url)
                if url and client.scope.is_in_scope(url):
                    return url
    for path in COMMON_LOGIN_PATHS:
        url = urljoin(target_url, path)
        r = client.get(url)
        if r is not None and r.status_code == 200 and find_login_form(r.text, r.url, client.scope):
            return r.url
    return None


def page_shows_logged_in(html, page_url, scope, username=None):
    """Heuristic: a logout link is present (or the username is displayed) and no password form."""
    soup = soup_of(html)
    has_logout = any(LOGOUT_RE.search(a.get_text(" ") or "") or LOGOUT_RE.search(a.get("href") or "")
                     for a in soup.find_all("a"))
    has_password_form = any(f.has_password_field() for f in parse_forms(soup, page_url, scope))
    shows_name = bool(username) and username.lower() in soup.get_text(" ").lower()
    return (has_logout or shows_name) and not has_password_form


def login(client, username, password, login_url):
    """Log ``client`` in. Returns a short status message or raises AuthenticationError."""
    resp = client.get(login_url)
    if resp is None:
        raise AuthenticationError(f"Login page {login_url} could not be reached.")
    form = find_login_form(resp.text, resp.url, client.scope)
    if form is None:
        raise AuthenticationError(f"No login form with a password field found at {login_url}.")

    data = form.default_data()  # keeps hidden fields such as CSRF tokens
    password_field = next(f.name for f in form.fields if f.type == "password")
    candidates = [f for f in form.fields if f.type in ("text", "email") and f.name != password_field]
    user_field = next((f.name for f in candidates if USERNAME_HINT.search(f.name)),
                      candidates[0].name if candidates else None)
    if user_field is None:
        raise AuthenticationError("Could not identify the username field of the login form.")
    data[user_field] = username
    data[password_field] = password

    if form.method == "POST":
        result = client.post(form.action, data=data)
    else:
        result = client.get(form.action, params=data)
    if result is None:
        raise AuthenticationError("The login request failed (network error).")
    if result.status_code >= 400:
        raise AuthenticationError(f"Login request returned HTTP {result.status_code}.")
    if not page_shows_logged_in(result.text, result.url, client.scope, username):
        # Some sites redirect to a page without the logout link; check the start page too.
        home = client.get(client.scope.target_url)
        if home is None or not page_shows_logged_in(home.text, home.url, client.scope, username):
            raise AuthenticationError("Login failed: credentials rejected or success could not be verified.")
    return "Login successful."


def find_user_id_hint(client):
    """Look for a link such as /profile/view?user_id=7 to learn the account's own id (informational)."""
    resp = client.get(client.scope.target_url)
    if resp is None:
        return None
    for url in extract_links(soup_of(resp.text), resp.url, client.scope):
        m = re.search(r"[?&](?:user_?id|uid|customer_?id|account_?id)=(\d+)", url, re.I)
        if m:
            return m.group(1)
    return None


class SessionManager:
    def __init__(self, scope, log, rate_limiter, counter, timeout):
        self._make = lambda label: HttpClient(scope, log, rate_limiter, counter, label=label, timeout=timeout)
        self.scope = scope
        self.anonymous = self._make("anonymous")
        self.sessions = []        # list[AuthSession]
        self.login_url = None

    def authenticate_all(self, credentials, login_url=None):
        """Log in every credential. Failures are recorded, not raised, so the scan can continue."""
        if not credentials:
            return []
        self.login_url = login_url or discover_login_url(self.anonymous, self.scope.target_url)
        for cred in credentials:
            client = self._make(cred.label)
            if not self.login_url:
                self.sessions.append(AuthSession(cred.label, cred.username, client, False,
                                                 "No login page could be found."))
                continue
            try:
                msg = login(client, cred.username, cred.password, self.login_url)
                session = AuthSession(cred.label, cred.username, client, True, msg)
                session.user_id_hint = find_user_id_hint(client)
            except AuthenticationError as exc:
                session = AuthSession(cred.label, cred.username, client, False, str(exc))
            self.sessions.append(session)
        return self.sessions

    @property
    def authenticated(self):
        return [s for s in self.sessions if s.authenticated]

    def primary_client(self):
        """The client used for crawling and injection tests: first logged-in user, else anonymous."""
        auth = self.authenticated
        return auth[0].client if auth else self.anonymous
