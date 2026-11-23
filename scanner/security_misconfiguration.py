"""Security misconfiguration detection.

Examines HTTP responses for:
  * missing Content-Security-Policy, X-Content-Type-Options and X-Frame-Options headers;
  * session cookies without the HttpOnly or SameSite attributes;
  * verbose error messages / exposed stack traces.

It analyses every response recorded during the scan (crawler, login and the
other modules' requests) and adds a few probes of its own: a request for a
non-existent page and one malformed value per discovered parameter.
Site-wide issues are aggregated into ONE finding per issue type so the report
is not flooded with one entry per page.
"""

import re
import secrets
from urllib.parse import urljoin

from .base import DetectionModule, send_point
from .html_utils import snippet
from .http_client import RequestBudgetExceeded
from .models import MISCONFIG, Finding

SESSION_COOKIE_RE = re.compile(r"sess|sid|auth|token|jwt|remember|login", re.I)

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)", r"File \"[^\"]+\.py\", line \d+",
    r"sqlite3\.\w+Error", r"\w+(?:Error|Exception): .{0,80}\n?\s*at [\w.$]+\(",
    r"at [\w.$]+\([\w]+\.java:\d+\)", r"Exception in thread \"", r"<b>(?:Fatal error|Warning)</b>:.{0,200} on line \d+",
    r"Stack trace:", r"System\.[\w.]+Exception", r"Werkzeug Debugger", r"Microsoft \.NET Framework Version",
    r"ActiveRecord::\w+", r"django\.\w+\.\w+Error", r"in [/\\][\w/\\.-]+\.php on line \d+",
]
STACK_TRACE_RE = re.compile("|".join(STACK_TRACE_PATTERNS), re.I)

MALFORMED_VALUE = "'\")vsx[]"


def parse_set_cookie(raw):
    """'name=value; Path=/; HttpOnly' -> ('name', {'path': '/', 'httponly': True})."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {}
    for p in parts[1:]:
        if not p:
            continue
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip() if v else True
    return name, attrs


def redact_cookie(raw):
    name, _, rest = raw.partition("=")
    _value, sep, attrs = rest.partition(";")
    return f"{name}=<redacted>{sep}{attrs}"


class SecurityMisconfigurationModule(DetectionModule):
    key = "misconfig"
    name = MISCONFIG

    def run(self, ctx):
        self.probe(ctx)
        records = [r for r in ctx.log.records if ctx.scope.is_in_scope(r.url)]
        findings = []
        for check in (self.check_headers, self.check_cookies, self.check_errors):
            try:
                findings.extend(check(ctx, records))
            except Exception as exc:
                ctx.notes.append(f"Misconfiguration check {check.__name__} failed: {exc}")
        return findings

    # -- active probes (read-only GET requests) -------------------------------
    def probe(self, ctx):
        ctx.progress("Misconfiguration: probing error handling")
        try:
            ctx.client.get(urljoin(ctx.scope.target_url, f"/vsx-nonexistent-{secrets.token_hex(4)}"))
            for point in ctx.crawl.injection_points:
                send_point(ctx.client, point, MALFORMED_VALUE)
        except RequestBudgetExceeded:
            ctx.notes.append("Misconfiguration probes stopped: request budget reached.")

    # -- 1. security headers --------------------------------------------------
    def check_headers(self, ctx, records):
        pages = [r for r in records if r.status == 200 and "html" in r.headers.get("Content-Type", "").lower()]
        if not pages:
            return []
        missing = {"Content-Security-Policy": [], "X-Content-Type-Options": [], "X-Frame-Options": []}
        seen_urls = set()
        for r in pages:
            if r.url in seen_urls:
                continue
            seen_urls.add(r.url)
            h = {k.lower(): v for k, v in r.headers.items()}
            csp = h.get("content-security-policy", "")
            if not csp:
                missing["Content-Security-Policy"].append(r.url)
            if h.get("x-content-type-options", "").lower() != "nosniff":
                missing["X-Content-Type-Options"].append(r.url)
            if not h.get("x-frame-options") and "frame-ancestors" not in csp.lower():
                missing["X-Frame-Options"].append(r.url)
        absent = {k: v for k, v in missing.items() if v}
        if not absent:
            return []
        total = len(seen_urls)
        parts = [f"{name} missing on {len(urls)}/{total} HTML pages (e.g. {urls[0]})" for name, urls in absent.items()]
        return [Finding(
            category=MISCONFIG, title="Missing security headers", url=ctx.scope.target_url,
            parameter=", ".join(absent), severity="", check="missing_security_headers", confidence="Confirmed",
            test_input="Inspection of HTTP response headers", evidence="; ".join(parts) + ".",
            description="Without these headers browsers apply weaker default protections against XSS, "
                        "MIME-type sniffing and clickjacking.",
        )]

    # -- 2. session cookie attributes ------------------------------------------
    def check_cookies(self, ctx, records):
        observed = {}  # cookie name -> list of (url, raw header)
        for r in records:
            for raw in r.set_cookies:
                name, attrs = parse_set_cookie(raw)
                if attrs.get("max-age") == "0" or "1970" in str(attrs.get("expires", "")):
                    continue  # cookie deletion, not a cookie being issued
                observed.setdefault(name, []).append((r.url, raw, attrs))
        if not observed:
            ctx.notes.append("Misconfiguration: no cookies were set by the target.")
            return []
        session_names = [n for n in observed if SESSION_COOKIE_RE.search(n)] or list(observed)
        findings = []
        for name in session_names:
            problems, example = set(), None
            for url, raw, attrs in observed[name]:
                bad = []
                if "httponly" not in attrs:
                    bad.append("HttpOnly")
                samesite = str(attrs.get("samesite", "")).lower()
                if samesite not in ("lax", "strict"):
                    bad.append("SameSite" if not samesite else f"SameSite={attrs['samesite']} (weak)")
                if ctx.scope.target_url.startswith("https") and "secure" not in attrs:
                    bad.append("Secure")
                if bad:
                    problems.update(bad)
                    example = example or (url, raw)
            if problems:
                findings.append(Finding(
                    category=MISCONFIG, title="Insecure session cookie attributes", url=ctx.scope.target_url,
                    parameter=name, severity="", check="insecure_session_cookie", confidence="Confirmed",
                    test_input="Inspection of Set-Cookie headers",
                    evidence=(f"Session cookie '{name}' is issued without: {', '.join(sorted(problems))}. "
                              f"Observed at {example[0]}: Set-Cookie: {redact_cookie(example[1])}"),
                    description="Without HttpOnly the cookie can be stolen by injected JavaScript; without SameSite "
                                "it is sent on cross-site requests, which enables CSRF.",
                ))
        return findings

    # -- 3. verbose errors -----------------------------------------------------
    def check_errors(self, ctx, records):
        hits = []
        for r in records:
            m = STACK_TRACE_RE.search(r.body or "")
            if m:
                hits.append((r, m.group(0)))
        if not hits:
            return []
        urls = sorted({r.url for r, _ in hits})
        first, match = hits[0]
        return [Finding(
            category=MISCONFIG, title="Verbose error messages / stack trace disclosure", url=ctx.scope.target_url,
            parameter=None, severity="", check="verbose_errors", confidence="Confirmed",
            test_input=f"{first.method} {first.url}",
            evidence=(f"{len(urls)} response(s) exposed technical error details (HTTP {first.status} for the first). "
                      f"Matched \"{match.strip()}\": {snippet(first.body, match, 120)} "
                      f"Affected requests include: {', '.join(urls[:5])}"),
            description="Stack traces reveal source paths, framework versions and SQL queries that help attackers.",
        )]
