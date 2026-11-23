"""Scope-enforcing, rate-limited HTTP client used for ALL scanner traffic.

Safety features implemented here (so no module can bypass them):
  * every request - including each redirect hop - is checked against Scope;
  * a global minimum delay between requests (rate limiting);
  * per-request timeouts;
  * a hard cap on the total number of requests per scan;
  * network errors are caught and logged instead of crashing the scan.

Every response is recorded in a shared ``ResponseLog`` which the security
misconfiguration module inspects (headers, Set-Cookie attributes, error pages).
"""

import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

import config


class RequestBudgetExceeded(RuntimeError):
    pass


@dataclass
class ResponseRecord:
    method: str
    url: str
    status: int
    headers: dict
    set_cookies: list
    body: str
    session_label: str


@dataclass
class ResponseLog:
    records: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    blocked: list = field(default_factory=list)

    def add(self, record):
        self.records.append(record)


class RateLimiter:
    """Shared between all clients of one scan, so two sessions cannot double the rate."""

    def __init__(self, delay):
        self.delay = max(0.0, float(delay))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        with self._lock:
            pause = self._last + self.delay - time.monotonic()
            if pause > 0:
                time.sleep(pause)
            self._last = time.monotonic()


class RequestCounter:
    def __init__(self, maximum):
        self.maximum = maximum
        self.count = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            if self.count >= self.maximum:
                raise RequestBudgetExceeded(f"Request limit of {self.maximum} reached.")
            self.count += 1


def raw_set_cookie_headers(resp):
    """Return each Set-Cookie header separately (requests merges them otherwise)."""
    try:
        values = resp.raw.headers.getlist("Set-Cookie")
        if values:
            return list(values)
    except AttributeError:
        pass
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []


class HttpClient:
    def __init__(self, scope, log, rate_limiter, counter, label="anonymous",
                 timeout=config.REQUEST_TIMEOUT):
        self.scope = scope
        self.log = log
        self.rate_limiter = rate_limiter
        self.counter = counter
        self.label = label
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = config.USER_AGENT

    def get(self, url, params=None, **kw):
        return self.request("GET", url, params=params, **kw)

    def post(self, url, data=None, **kw):
        return self.request("POST", url, data=data, **kw)

    def request(self, method, url, params=None, data=None, allow_redirects=True):
        """Send a request, following in-scope redirects manually. Returns a Response or None."""
        history = []
        for _hop in range(config.MAX_REDIRECTS + 1):
            if not self.scope.is_in_scope(url):
                self.log.blocked.append(url)
                return history[-1] if history else None
            self.counter.increment()  # may raise RequestBudgetExceeded (handled by the engine)
            self.rate_limiter.wait()
            try:
                resp = self.session.request(method, url, params=params, data=data,
                                            timeout=self.timeout, allow_redirects=False)
            except requests.exceptions.RequestException as exc:
                self.log.errors.append(f"{method} {url}: {type(exc).__name__}: {exc}")
                return None
            self._record(method, resp)
            if not (allow_redirects and resp.is_redirect and resp.headers.get("Location")):
                resp.history = history
                return resp
            history.append(resp)
            url = urljoin(resp.url, resp.headers["Location"])
            params = None
            if resp.status_code in (301, 302, 303) and method == "POST":
                method, data = "GET", None
        self.log.errors.append(f"Too many redirects starting from {url}")
        return history[-1] if history else None

    def _record(self, method, resp):
        try:
            body = resp.text[: config.MAX_BODY_CHARS]
        except Exception:  # undecodable / malformed body
            body = ""
        self.log.add(ResponseRecord(
            method=method, url=resp.url, status=resp.status_code,
            headers=dict(resp.headers), set_cookies=raw_set_cookie_headers(resp),
            body=body, session_label=self.label,
        ))


def is_html(resp):
    return resp is not None and "html" in resp.headers.get("Content-Type", "").lower()
