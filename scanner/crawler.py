"""Breadth-first website crawler restricted to the authorised target.

Discovers internal pages, links, forms and URL parameters, and records which
pages require authentication. Only GET requests are made while crawling; forms
are recorded but never submitted, and links matching
``config.EXCLUDED_LINK_PATTERNS`` (e.g. logout) are never followed.
"""

import re
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import config

from .authentication import LOGIN_RE, find_login_form
from .html_utils import extract_links, page_title, parse_forms, soup_of
from .http_client import RequestBudgetExceeded, is_html
from .models import InjectionPoint, Page

INPUT_FIELD_TYPES = {"text", "search", "email", "number", "textarea", "select", "hidden", "tel", "url"}


def strip_query(url):
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def endpoint_signature(url):
    """/product?id=1 and /product?id=2 share the signature ('/product', ('id',))."""
    p = urlparse(url)
    return p.path, tuple(sorted(k for k, _ in parse_qsl(p.query, keep_blank_values=True)))


@dataclass
class CrawlResult:
    session_label: str
    pages: dict = field(default_factory=dict)          # url -> Page
    forms: list = field(default_factory=list)          # unique Form objects
    injection_points: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    skipped: list = field(default_factory=list)

    @property
    def urls(self):
        return list(self.pages)

    def summary(self):
        return {
            "session": self.session_label,
            "pages": len(self.pages),
            "forms": len(self.forms),
            "parameters": len(self.injection_points),
            "auth_required_pages": sum(1 for p in self.pages.values() if p.requires_auth),
            "errors": len(self.errors),
        }


class Crawler:
    def __init__(self, client, max_pages=config.MAX_PAGES, max_depth=config.MAX_DEPTH,
                 excluded_patterns=None, progress=None):
        self.client = client
        self.scope = client.scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.excluded = [re.compile(p, re.I) for p in (excluded_patterns or config.EXCLUDED_LINK_PATTERNS)]
        self.progress = progress or (lambda msg: None)

    def _excluded(self, url):
        return any(p.search(url) for p in self.excluded)

    def crawl(self, start_url):
        result = CrawlResult(session_label=self.client.label)
        queue = deque([(start_url, 0)])
        seen = {start_url}
        variants = {}
        form_signatures = set()

        while queue and len(result.pages) < self.max_pages:
            url, depth = queue.popleft()
            try:
                resp = self.client.get(url)
            except RequestBudgetExceeded:
                result.errors.append("Request budget exhausted during crawl.")
                break
            if resp is None:
                result.errors.append(f"Unreachable: {url}")
                continue

            final_url = resp.url
            if not self.scope.is_in_scope(final_url):
                result.skipped.append(url)
                continue
            soup = soup_of(resp.text) if is_html(resp) else None
            page = Page(url=url, status=resp.status_code,
                        content_type=resp.headers.get("Content-Type", ""), depth=depth,
                        session_label=self.client.label, title=page_title(soup) if soup else "")
            # A redirect to a login page means this URL needs authentication.
            if resp.history and strip_query(final_url) != strip_query(url) and \
                    (LOGIN_RE.search(final_url) or (soup and find_login_form(resp.text, final_url, self.scope))):
                page.requires_auth = True
            elif resp.status_code in (401, 403):
                page.requires_auth = True
            result.pages[url] = page
            self.progress(f"[{self.client.label}] crawled {len(result.pages)}: {url} ({resp.status_code})")

            if soup is None or resp.status_code >= 400:
                continue

            for form in parse_forms(soup, final_url, self.scope):
                if not self.scope.is_in_scope(form.action):
                    continue
                if form.signature() not in form_signatures:
                    form_signatures.add(form.signature())
                    result.forms.append(form)

            if depth >= self.max_depth:
                continue
            for link in extract_links(soup, final_url, self.scope):
                if link in seen:
                    continue
                seen.add(link)
                if not self.scope.is_in_scope(link):
                    result.skipped.append(link)   # external domain - never followed
                    continue
                if self._excluded(link):
                    result.skipped.append(link)
                    continue
                sig = endpoint_signature(link)
                variants[sig] = variants.get(sig, 0) + 1
                if sig[1] and variants[sig] > config.MAX_VARIANTS_PER_ENDPOINT:
                    continue
                queue.append((link, depth + 1))

        result.injection_points = self._injection_points(result)
        return result

    def _injection_points(self, result):
        points, keys = [], set()

        def add(point):
            if point.key() not in keys:
                keys.add(point.key())
                points.append(point)

        for url, page in result.pages.items():
            if page.status >= 400:
                continue
            query = parse_qsl(urlparse(url).query, keep_blank_values=True)
            params = dict(query)
            for name, _value in query:
                add(InjectionPoint(strip_query(url), "GET", name, params, "link"))
        for form in result.forms:
            if form.method != "GET":
                continue  # POST forms are not fuzzed (state-changing); see the CSRF module
            data = form.default_data()
            for f in form.fields:
                if f.type in INPUT_FIELD_TYPES:
                    add(InjectionPoint(strip_query(form.action), "GET", f.name, data, "form"))
        return points

    def classify_authentication(self, result, anonymous_client):
        """For pages fetched with a logged-in session, test whether they are reachable anonymously."""
        if self.client is anonymous_client:
            return
        for url, page in result.pages.items():
            if page.requires_auth is not None or page.status >= 400:
                continue
            try:
                resp = anonymous_client.get(url)
            except RequestBudgetExceeded:
                return
            if resp is None:
                continue
            redirected_to_login = bool(resp.history) and (
                LOGIN_RE.search(resp.url) or find_login_form(resp.text, resp.url, self.scope))
            page.requires_auth = bool(redirected_to_login or resp.status_code in (401, 403))


def build_url(base, params):
    return base + ("?" + urlencode(params) if params else "")
