"""The scanner copes with unavailable sites, failed logins, malformed responses and broken pages."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scanner.crawler import Crawler
from scanner.detection_engine import ScanEngine
from scanner.html_utils import parse_forms, soup_of
from scanner.http_client import HttpClient, RateLimiter, RequestBudgetExceeded, RequestCounter, ResponseLog
from scanner.target_validation import Scope, TargetValidationError
from tests.conftest import make_config


class BrokenHandler(BaseHTTPRequestHandler):
    """A tiny server with malformed HTML, a 500 page, binary data and an external link."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/":
            body, ctype, code = ('<html><body><a href="/broken">b</a><a href="/missing">m</a>'
                                 '<a href="/bin">x</a><a href="http://external.example/">ext</a>'
                                 '<form action="/s"><input name="q"<div></form><p><b>unclosed'), "text/html", 200
        elif self.path == "/broken":
            body, ctype, code = "<h1>Server Error</h1>", "text/html", 500
        elif self.path == "/bin":
            body, ctype, code = "\x00\xff\xfe binary", "application/octet-stream", 200
        else:
            body, ctype, code = "not found", "text/plain", 404
        data = body.encode("latin-1")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def broken_site():
    srv = HTTPServer(("127.0.0.1", 0), BrokenHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/"
    srv.shutdown()


def test_unavailable_website_gives_clear_error():
    with pytest.raises(TargetValidationError):
        ScanEngine(make_config("http://127.0.0.1:1/", users=())).run()


def test_scan_of_broken_site_completes(broken_site):
    result = ScanEngine(make_config(broken_site, users=())).run()
    pages = {p["url"]: p["status"] for p in result["discovered"]["pages"]}
    assert pages[broken_site + "broken"] == 500 and pages[broken_site + "missing"] == 404
    assert not any("external.example" in u for u in pages)
    assert all(m["status"] == "completed" for m in result["modules"].values())


def test_failed_login_does_not_stop_scan(vulnerable_server):
    result = ScanEngine(make_config(vulnerable_server.url, users=(("alice", "bad"), ("bob", "bad")))).run()
    assert not any(s["authenticated"] for s in result["sessions"])
    assert any("unauthenticated" in n for n in result["notes"])
    assert result["summary"]["total"] > 0  # public-page checks still ran


def test_network_error_returns_none_and_is_logged():
    scope = Scope("http://127.0.0.1:1/")
    log = ResponseLog()
    client = HttpClient(scope, log, RateLimiter(0), RequestCounter(10), timeout=1)
    assert client.get("http://127.0.0.1:1/page") is None and log.errors


def test_out_of_scope_requests_are_blocked():
    log = ResponseLog()
    client = HttpClient(Scope("http://127.0.0.1:1/"), log, RateLimiter(0), RequestCounter(10))
    assert client.get("http://example.com/") is None and log.blocked == ["http://example.com/"]


def test_request_budget(broken_site):
    client = HttpClient(Scope(broken_site), ResponseLog(), RateLimiter(0), RequestCounter(1))
    client.get(broken_site)
    with pytest.raises(RequestBudgetExceeded):
        client.get(broken_site)


def test_malformed_html_is_parsed():
    forms = parse_forms(soup_of('<form action="/s"><input name="q"<div></form><p><b>'), "http://h/",
                        Scope("http://h/"))
    assert forms and forms[0].action == "http://h/s"


def test_crawler_handles_inaccessible_pages(broken_site):
    client = HttpClient(Scope(broken_site), ResponseLog(), RateLimiter(0), RequestCounter(100))
    result = Crawler(client).crawl(broken_site)
    assert len(result.pages) == 4
    assert "http://external.example/" in result.skipped
