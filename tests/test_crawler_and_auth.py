"""Crawler discovery and authenticated sessions with two accounts."""

from scanner.authentication import SessionManager
from scanner.crawler import Crawler
from scanner.http_client import RateLimiter, RequestCounter, ResponseLog
from scanner.models import Credential
from scanner.target_validation import Scope
from tests.conftest import ALICE, BOB


def manager(url):
    return SessionManager(Scope(url), ResponseLog(), RateLimiter(0), RequestCounter(2000), 5)


def test_two_accounts_log_in(vulnerable_server):
    sm = manager(vulnerable_server.url)
    sm.authenticate_all([Credential(*ALICE, "user_a"), Credential(*BOB, "user_b")])
    assert [s.authenticated for s in sm.sessions] == [True, True]
    # Each account has its own cookie jar and sees its own profile id.
    assert {s.user_id_hint for s in sm.sessions} == {"1", "2"}


def test_failed_login_is_reported_not_raised(vulnerable_server):
    sm = manager(vulnerable_server.url)
    sm.authenticate_all([Credential("alice", "wrong-password", "user_a")])
    assert sm.sessions[0].authenticated is False
    assert "failed" in sm.sessions[0].message.lower()
    assert sm.primary_client() is sm.anonymous


def test_login_works_with_csrf_protected_form(patched_server):
    sm = manager(patched_server.url)
    sm.authenticate_all([Credential(*ALICE, "user_a")])
    assert sm.sessions[0].authenticated


def test_anonymous_crawl_finds_public_pages_and_forms(vulnerable_server):
    sm = manager(vulnerable_server.url)
    result = Crawler(sm.anonymous).crawl(vulnerable_server.url)
    paths = {u.replace(vulnerable_server.url.rstrip("/"), "") for u in result.pages}
    assert {"/", "/products", "/login", "/register"} <= paths
    assert any(p.startswith("/product?id=") for p in paths)
    assert any(f.action.endswith("/search") and f.method == "GET" for f in result.forms)
    assert any(ip.param == "q" for ip in result.injection_points)
    assert all(sm.scope.is_in_scope(u) for u in result.pages)


def test_authenticated_crawl_finds_user_pages_and_marks_auth(vulnerable_server):
    sm = manager(vulnerable_server.url)
    sm.authenticate_all([Credential(*ALICE, "user_a")])
    crawler = Crawler(sm.primary_client())
    result = crawler.crawl(vulnerable_server.url)
    crawler.classify_authentication(result, sm.anonymous)
    by_path = {u.replace(vulnerable_server.url.rstrip("/"), ""): p for u, p in result.pages.items()}
    assert "/orders" in by_path and by_path["/orders"].requires_auth is True
    assert by_path["/products"].requires_auth is False
    assert any(p.startswith("/order?id=") for p in by_path)
    assert not any("logout" in p for p in by_path), "logout links must never be followed"
    assert any(f.method == "POST" and f.action.endswith("/profile/update") for f in result.forms)


def test_crawl_limit_is_respected(vulnerable_server):
    sm = manager(vulnerable_server.url)
    result = Crawler(sm.anonymous, max_pages=3).crawl(vulnerable_server.url)
    assert len(result.pages) == 3
