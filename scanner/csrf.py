"""Cross-Site Request Forgery (CSRF) detection.

1. State-changing forms are identified: POST forms discovered while logged in,
   excluding authentication forms (forms containing a password field, i.e.
   login/registration).
2. Each form is checked for an anti-CSRF token (a hidden field whose name looks
   like csrf/xsrf/token/authenticity/nonce).
3. ACTIVE verification (only against local hosts - see
   ``config.ACTIVE_TESTS_LOCAL_ONLY``): the form is submitted with its
   *existing* values (so e.g. a profile update writes back the same data)
   but WITHOUT the token, and - if the form had a token - again with a forged
   token. If the server accepts the request, a CSRF finding is confirmed.
4. For non-local targets, no forms are submitted; a missing token is reported
   only as a *Tentative* finding so that no unverified claim is made.

Note: the checkout form is submitted while the test account's cart is empty,
so no order is actually placed; the server either processes the request
("cart is empty") or rejects it because the token is missing.
"""

import re
import secrets

from .authentication import LOGIN_RE, find_login_form
from .base import DetectionModule
from .html_utils import parse_forms, soup_of
from .http_client import RequestBudgetExceeded
from .models import CSRF, Finding

TOKEN_NAME_RE = re.compile(r"csrf|xsrf|token|authenticity|nonce|__requestverification", re.I)
REJECTION_RE = re.compile(
    r"csrf|xsrf|request forgery|invalid (?:or missing )?token|token (?:is )?(?:missing|invalid|expired|mismatch)"
    r"|security token|forbidden|bad request", re.I)


def token_fields(form):
    return [f for f in form.fields if f.type == "hidden" and TOKEN_NAME_RE.search(f.name)]


def is_state_changing(form):
    return form.method == "POST" and not form.has_password_field()


def request_accepted(resp, scope):
    """Decide whether the server processed the submission (True) or rejected it (False)."""
    if resp is None or resp.status_code >= 400:
        return False
    if resp.history and (LOGIN_RE.search(resp.url) or find_login_form(resp.text, resp.url, scope)):
        return False  # bounced to the login page -> session not accepted
    text = soup_of(resp.text).get_text(" ")
    return not REJECTION_RE.search(text)


def describe(resp):
    if resp is None:
        return "no response"
    hops = " -> ".join(f"HTTP {h.status_code}" for h in resp.history)
    return (hops + " -> " if hops else "") + f"HTTP {resp.status_code} at {resp.url}"


class CSRFModule(DetectionModule):
    key = "csrf"
    name = CSRF

    def run(self, ctx):
        findings = []
        if not ctx.sessions.authenticated:
            ctx.notes.append("CSRF: no authenticated session - state-changing forms behind login were not tested.")
        if not ctx.active_tests_allowed:
            ctx.notes.append("CSRF: target is not a local host, so forms were NOT submitted (passive checks only).")
        for form in ctx.crawl.forms:
            if not is_state_changing(form):
                continue
            ctx.progress(f"CSRF: checking form {form.method} {form.action}")
            try:
                finding = self.test_form(ctx, form)
            except RequestBudgetExceeded:
                raise
            except Exception as exc:
                ctx.notes.append(f"CSRF test error on {form.action}: {exc}")
                continue
            if finding:
                findings.append(finding)
        return findings

    def test_form(self, ctx, form):
        tokens = token_fields(form)
        fields = ", ".join(n for n in form.field_names()) or "(none)"

        if not ctx.active_tests_allowed:
            if tokens:
                return None
            return Finding(
                category=CSRF, title="Form without anti-CSRF token (unverified)", url=form.action,
                parameter=None, severity="", method="POST", test_input=f"Form fields: {fields}",
                check="missing_token_passive", confidence="Tentative",
                evidence=(f"State-changing POST form on {form.page_url} contains no hidden anti-CSRF token. "
                          "Server-side validation was not tested because active tests are limited to local targets."),
                description="The form may be vulnerable to CSRF; manual verification is required.",
            )

        # Re-read the page so the form values (and any token) belong to the current session.
        page = ctx.client.get(form.page_url)
        if page is not None:
            fresh = [f for f in parse_forms(soup_of(page.text), page.url, ctx.scope)
                     if f.signature()[:2] == form.signature()[:2]]
            if fresh:
                form = fresh[0]
                tokens = token_fields(form)

        base_data = form.default_data()
        token_names = {t.name for t in tokens}
        attempts = [("token removed", {k: v for k, v in base_data.items() if k not in token_names})]
        if tokens:
            forged = dict(base_data)
            for name in token_names:
                forged[name] = secrets.token_hex(16)
            attempts.append(("forged token", forged))

        for label, data in attempts:
            resp = ctx.client.post(form.action, data=data)
            if request_accepted(resp, ctx.scope):
                had = (f"The form contains token field(s) {sorted(token_names)}, but the server did not validate them. "
                       if tokens else "The form contains no anti-CSRF token. ")
                return Finding(
                    category=CSRF, title="Cross-site request forgery", url=form.action, parameter=None,
                    severity="", method="POST", check="token_not_validated" if tokens else "missing_token",
                    confidence="Confirmed",
                    test_input=f"POST {form.action} with {label}; fields submitted: {', '.join(data) or '(none)'}",
                    evidence=(had + f"A POST request with the {label} was ACCEPTED: {describe(resp)}. "
                              f"Form found on {form.page_url}. Original values were re-submitted, so no data changed."),
                    description="A malicious site could make a logged-in victim's browser submit this request "
                                "without their knowledge.",
                )
        return None
