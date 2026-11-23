"""The scanner accepts and validates target URLs and enforces scope."""

import pytest

from scanner.target_validation import (Scope, TargetValidationError, check_reachable, is_local_host,
                                       validate_target_url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:5001/", "https://shop.example.com", "http://localhost:8080/shop?x=1"])
def test_valid_urls_are_accepted(url):
    assert validate_target_url(url).startswith(("http://", "https://"))


@pytest.mark.parametrize("url", ["", None, "127.0.0.1:5001", "ftp://example.com", "http://", "javascript:alert(1)",
                                 "http://user:pw@example.com/", "http://exa mple.com/", "http://host:99999/"])
def test_invalid_urls_are_rejected(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url)


def test_url_is_normalised():
    assert validate_target_url("  http://LOCALHOST:5001  ") == "http://localhost:5001/"


def test_scope_restricts_to_same_origin():
    scope = Scope("http://127.0.0.1:5001/")
    assert scope.is_in_scope("http://127.0.0.1:5001/products?x=1")
    assert not scope.is_in_scope("http://127.0.0.1:5002/")          # different port
    assert not scope.is_in_scope("https://127.0.0.1:5001/")         # different scheme
    assert not scope.is_in_scope("http://evil.example.com/")        # external domain


def test_scope_normalise_drops_non_http_links():
    scope = Scope("http://127.0.0.1:5001/")
    assert scope.normalise("mailto:x@y.z") is None
    assert scope.normalise("javascript:void(0)") is None
    assert scope.normalise("/cart#top") == "http://127.0.0.1:5001/cart"


def test_local_host_detection():
    assert is_local_host("http://127.0.0.1:5001/") and is_local_host("http://localhost/")
    assert not is_local_host("https://example.com/")


def test_reachability_of_live_target(vulnerable_server):
    ok, status = check_reachable(vulnerable_server.url)
    assert ok and status == 200


def test_unreachable_target_raises_clean_error():
    with pytest.raises(TargetValidationError, match="unreachable"):
        check_reachable("http://127.0.0.1:1/", timeout=2)
