"""HTML parsing and response-comparison helpers (BeautifulSoup based)."""

import difflib
import html as html_lib
import re
import warnings

from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning

from .models import Form, FormField

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


def soup_of(text):
    try:
        return BeautifulSoup(text or "", "html.parser")
    except Exception:  # malformed markup should never crash the scan
        return BeautifulSoup("", "html.parser")


def extract_links(soup, page_url, scope):
    """Return absolute URLs from <a href>, <link href>, <area href> and <iframe src>."""
    links = []
    for tag, attr in (("a", "href"), ("area", "href"), ("iframe", "src")):
        for el in soup.find_all(tag):
            url = scope.normalise(el.get(attr), base=page_url)
            if url:
                links.append(url)
    return links


def parse_forms(soup, page_url, scope):
    """Extract every <form> with its action, method and input fields."""
    forms = []
    for f in soup.find_all("form"):
        action = scope.normalise(f.get("action") or page_url, base=page_url) or page_url
        method = (f.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        fields = []
        for el in f.find_all(["input", "textarea", "select", "button"]):
            name = el.get("name")
            if not name:
                continue
            if el.name == "textarea":
                fields.append(FormField(name, "textarea", el.text or ""))
            elif el.name == "select":
                opt = el.find("option", selected=True) or el.find("option")
                fields.append(FormField(name, "select", (opt.get("value", opt.text) if opt else "")))
            elif el.name == "button":
                fields.append(FormField(name, "submit", el.get("value", "")))
            else:
                ftype = (el.get("type") or "text").lower()
                if ftype in ("checkbox", "radio") and not el.has_attr("checked"):
                    continue
                fields.append(FormField(name, ftype, el.get("value", "")))
        forms.append(Form(page_url=page_url, action=action, method=method, fields=fields))
    return forms


def page_title(soup):
    return soup.title.get_text(strip=True) if soup.title else ""


def visible_text(text, remove=()):
    """Plain page text used for similarity comparisons.

    ``remove`` holds strings (e.g. the injected payload) to strip first, so that
    a page merely *echoing* the payload does not look "different".
    """
    for r in remove:
        if r:
            text = text.replace(r, "").replace(html_lib.escape(r), "").replace(html_lib.escape(r, quote=False), "")
    soup = soup_of(text)
    for s in soup(["script", "style"]):
        s.decompose()
    txt = soup.get_text(" ")
    return re.sub(r"\s+", " ", txt).strip()[:20000]


def similarity(a, b):
    """Ratio in [0, 1]; 1.0 means identical."""
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def snippet(text, needle, width=80):
    """Return the text surrounding ``needle`` (for evidence)."""
    idx = text.find(needle)
    if idx < 0:
        return ""
    start, end = max(0, idx - width), min(len(text), idx + len(needle) + width)
    return ("…" if start else "") + text[start:end].replace("\n", " ") + ("…" if end < len(text) else "")
