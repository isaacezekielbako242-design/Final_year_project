"""Broken Access Control (IDOR / missing ownership checks) detection.

Requires two authenticated test accounts (user A and user B):

1. Both sessions crawl the site. A URL is treated as a *user-specific
   resource* of A when it (a) requires authentication, (b) carries an
   identifier-like parameter (id, user_id, order_id, ...), and (c) was found
   in A's crawl but NOT in B's (B has no link to it).
2. The resource is requested with A's session (owner's view) and then with
   B's session (cross-user attempt).
3. A finding is reported when B receives an HTTP 200 page (not a login
   redirect, 403 or 404) whose content closely matches A's view - i.e. B can
   read A's protected information. Whether A's username appears in B's
   response is added as extra evidence.

The same test is repeated in the opposite direction (B's resources with A's session).
Only GET requests are made; nothing is modified.
"""

import re
from urllib.parse import parse_qsl, urlparse

from .authentication import LOGIN_RE, find_login_form
from .base import DetectionModule, comparable_text
from .crawler import strip_query
from .html_utils import similarity
from .http_client import RequestBudgetExceeded
from .models import BAC, Finding, mask

ID_PARAM_RE = re.compile(r"(^|_)(id|uid|user|order|account|customer|profile|invoice|number|no)(_?id)?$", re.I)
SIMILARITY_REQUIRED = 0.80


def id_params(url):
    return [(k, v) for k, v in parse_qsl(urlparse(url).query) if ID_PARAM_RE.search(k)]


class BrokenAccessControlModule(DetectionModule):
    key = "bac"
    name = BAC

    def run(self, ctx):
        sessions = [s for s in ctx.sessions.authenticated if s.label in ctx.crawls]
        if len(sessions) < 2:
            ctx.notes.append("Broken access control: two successfully authenticated test accounts are required; "
                             "module skipped.")
            return []

        findings, confirmed = [], set()
        for owner in sessions:
            for other in sessions:
                if owner is other:
                    continue
                for url in self.candidate_urls(ctx.crawls[owner.label], ctx.crawls[other.label]):
                    for param, _ in id_params(url):
                        key = (strip_query(url), param)
                        if key in confirmed:
                            continue  # already proven for this endpoint/parameter
                        ctx.progress(f"Access control: {other.label} -> {owner.label}'s {url}")
                        try:
                            f = self.test_resource(ctx, url, param, owner, other)
                        except RequestBudgetExceeded:
                            raise
                        except Exception as exc:
                            ctx.notes.append(f"Access-control test error on {url}: {exc}")
                            continue
                        if f:
                            confirmed.add(key)
                            findings.append(f)
        return findings

    @staticmethod
    def candidate_urls(owner_crawl, other_crawl):
        other_urls = set(other_crawl.pages)
        out = []
        for url, page in owner_crawl.pages.items():
            if page.status == 200 and page.requires_auth and id_params(url) and url not in other_urls:
                out.append(url)
        return out

    def test_resource(self, ctx, url, param, owner, other):
        owner_resp = owner.client.get(url)
        other_resp = other.client.get(url)
        if owner_resp is None or other_resp is None or owner_resp.status_code != 200:
            return None
        if other_resp.status_code != 200:
            return None  # 403/404/... -> ownership enforced
        if strip_query(other_resp.url) != strip_query(url) and (
                LOGIN_RE.search(other_resp.url) or find_login_form(other_resp.text, other_resp.url, ctx.scope)):
            return None  # redirected to login

        owner_txt = comparable_text(owner_resp)
        other_txt = comparable_text(other_resp)
        # Remove each user's own navigation label (e.g. "Profile (bob)") before comparing.
        for s in (owner, other):
            owner_txt = owner_txt.replace(s.username, "")
            other_txt = other_txt.replace(s.username, "")
        ratio = similarity(owner_txt, other_txt)
        if ratio < SIMILARITY_REQUIRED:
            return None

        leaked_name = owner.username.lower() in other_resp.text.lower()
        value = dict(parse_qsl(urlparse(url).query)).get(param, "")
        return Finding(
            category=BAC, title="Broken access control (insecure direct object reference)",
            url=strip_query(url), parameter=param, severity="", check="cross_user_access",
            confidence="Confirmed",
            test_input=f"{param}={value} (a resource of {owner.label}) requested with {other.label}'s session",
            evidence=(f"{owner.label}'s resource {url} was returned to {other.label} with HTTP 200. "
                      f"The response is {ratio:.0%} similar to the owner's own view"
                      + (f" and contains the owner's username ({mask(owner.username)})" if leaked_name else "")
                      + ". The application does not verify that the requested object belongs to the logged-in user."),
            description="One customer can read another customer's protected data by changing an identifier in the URL.",
        )
