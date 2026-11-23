"""HTML security report generation (Jinja2)."""

import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config

from .models import CATEGORIES, SEVERITIES

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

CATEGORY_INFO = {
    "SQL Injection": "Untrusted input changes the structure of database queries.",
    "Cross-Site Scripting (XSS)": "Untrusted input is returned to the browser without encoding (reflected XSS only).",
    "Cross-Site Request Forgery (CSRF)": "State-changing requests are accepted without proof that the user intended them.",
    "Broken Access Control": "Users can access resources that belong to other users.",
    "Security Misconfiguration": "Missing hardening: security headers, cookie attributes, error handling.",
}

_env = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=select_autoescape(["html"]))


def render_report(result, evaluation=None):
    """Render a scan result dict (from ScanEngine.run) to an HTML string.

    All values are auto-escaped, so evidence containing payloads such as
    ``<vsx…tag>`` is displayed as text and never executed in the report.
    """
    groups = {c: [f for f in result["findings"] if f["category"] == c] for c in CATEGORIES}
    template = _env.get_template("report.html")
    return template.render(r=result, groups=groups, categories=CATEGORIES, severities=SEVERITIES,
                           category_info=CATEGORY_INFO, evaluation=evaluation)


def save_report(result, directory=config.REPORTS_DIR, evaluation=None):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"scan_{result['scan_id']}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_report(result, evaluation))
    return path
