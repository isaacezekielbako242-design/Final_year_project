"""Shared data structures used across the scanner modules."""

from dataclasses import asdict, dataclass, field
from typing import Optional

# Vulnerability category names (used everywhere, including the ground truth).
SQLI = "SQL Injection"
XSS = "Cross-Site Scripting (XSS)"
CSRF = "Cross-Site Request Forgery (CSRF)"
BAC = "Broken Access Control"
MISCONFIG = "Security Misconfiguration"
CATEGORIES = [SQLI, XSS, CSRF, BAC, MISCONFIG]

SEVERITIES = ["High", "Medium", "Low"]


@dataclass
class Credential:
    """A test account. Passwords are never written to reports (see ScanConfig.public_dict)."""
    username: str
    password: str
    label: str = "user"


@dataclass
class ScanConfig:
    target_url: str
    authorized: bool = False
    credentials: list = field(default_factory=list)  # list[Credential]
    login_url: Optional[str] = None
    max_pages: int = 60
    max_depth: int = 4
    request_delay: float = 0.05
    timeout: float = 10
    modules: list = field(default_factory=lambda: ["sqli", "xss", "csrf", "bac", "misconfig"])

    def public_dict(self):
        """Configuration safe to place in reports: no passwords, masked usernames."""
        return {
            "target_url": self.target_url,
            "authorized_confirmed": self.authorized,
            "test_accounts": [f"{c.label}: {mask(c.username)}" for c in self.credentials],
            "login_url": self.login_url,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "request_delay": self.request_delay,
            "timeout": self.timeout,
            "modules": list(self.modules),
        }


def mask(value):
    if not value:
        return ""
    return value[0] + "*" * max(len(value) - 2, 1) + (value[-1] if len(value) > 2 else "")


@dataclass
class FormField:
    name: str
    type: str = "text"
    value: str = ""


@dataclass
class Form:
    page_url: str           # page on which the form was found
    action: str             # absolute URL the form submits to
    method: str             # "GET" or "POST"
    fields: list = field(default_factory=list)  # list[FormField]

    def field_names(self):
        return [f.name for f in self.fields]

    def has_password_field(self):
        return any(f.type == "password" for f in self.fields)

    def default_data(self):
        return {f.name: f.value for f in self.fields if f.type not in ("submit", "button", "image", "reset")}

    def signature(self):
        return (self.method, self.action.split("?")[0], tuple(sorted(self.field_names())))


@dataclass
class Page:
    url: str
    status: int
    content_type: str = ""
    depth: int = 0
    requires_auth: Optional[bool] = None   # None = not checked
    session_label: str = "anonymous"
    title: str = ""


@dataclass
class InjectionPoint:
    """A single user-controllable input: a URL query parameter or a GET form field."""
    url: str              # base URL without the query string
    method: str           # "GET" (POST forms are handled only by the CSRF module)
    param: str
    params: dict          # all parameters with their original values
    source: str           # "link" or "form"

    def key(self):
        return (self.method, self.url, self.param)


@dataclass
class Finding:
    category: str
    title: str
    url: str
    parameter: Optional[str]
    severity: str
    test_input: Optional[str]
    evidence: str
    description: str = ""
    check: str = ""            # machine-readable check id, e.g. "error_based", "missing_headers"
    confidence: str = "Firm"   # "Confirmed", "Firm" or "Tentative"
    method: str = "GET"
    remediation: str = ""
    finding_id: str = ""

    def to_dict(self):
        return asdict(self)
