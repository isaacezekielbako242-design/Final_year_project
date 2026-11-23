"""Target URL validation and scope control.

* ``validate_target_url`` - checks syntax (http/https, host present, no
  embedded credentials) and returns a normalised URL.
* ``Scope``               - decides whether a URL belongs to the authorised
  target (same scheme + host + port). Every HTTP request made by the scanner
  goes through ``Scope.is_in_scope`` via ``HttpClient``.
* ``check_reachable``     - confirms the target answers before scanning.
"""

from urllib.parse import urldefrag, urljoin, urlparse, urlunparse

import requests

import config


class TargetValidationError(ValueError):
    """Raised when the target URL is invalid, unreachable or not authorised."""


def validate_target_url(url):
    if not url or not isinstance(url, str):
        raise TargetValidationError("A target URL is required.")
    url = url.strip()
    if "://" not in url:
        raise TargetValidationError("The URL must start with http:// or https://")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise TargetValidationError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise TargetValidationError("The URL does not contain a host name.")
    if parsed.username or parsed.password:
        raise TargetValidationError("Do not embed credentials in the URL; use the credential fields.")
    if any(ch.isspace() for ch in url):
        raise TargetValidationError("The URL must not contain spaces.")
    try:
        _ = parsed.port  # raises ValueError for invalid ports
    except ValueError as exc:
        raise TargetValidationError(f"Invalid port: {exc}") from None
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", parsed.query, ""))


def is_local_host(url):
    return (urlparse(url).hostname or "").lower() in config.LOCAL_HOSTS


def check_reachable(url, timeout=config.REQUEST_TIMEOUT):
    """Return (True, status_code) or raise TargetValidationError."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False,
                            headers={"User-Agent": config.USER_AGENT})
    except requests.exceptions.ConnectionError:
        raise TargetValidationError(f"Target {url} is unreachable (connection refused or DNS failure).") from None
    except requests.exceptions.Timeout:
        raise TargetValidationError(f"Target {url} did not respond within {timeout} seconds.") from None
    except requests.exceptions.RequestException as exc:
        raise TargetValidationError(f"Could not contact target: {exc}") from None
    return True, resp.status_code


def _origin(url):
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme, (p.hostname or "").lower(), port)


class Scope:
    """Restricts all scanner traffic to the authorised target origin."""

    def __init__(self, target_url):
        self.target_url = target_url
        self.origin = _origin(target_url)

    def is_in_scope(self, url):
        try:
            return _origin(url) == self.origin
        except ValueError:
            return False

    def normalise(self, url, base=None):
        """Resolve relative links, strip fragments and return None for non-HTTP links."""
        if not url:
            return None
        url = url.strip()
        if url.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return None
        absolute = urldefrag(urljoin(base or self.target_url, url))[0]
        if urlparse(absolute).scheme not in ("http", "https"):
            return None
        return absolute
