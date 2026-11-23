"""Shared context object and helpers for the detection modules."""

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import quote_plus

from .html_utils import visible_text


@dataclass
class DetectionContext:
    scan_config: object            # ScanConfig
    scope: object                  # Scope
    sessions: object               # SessionManager
    client: object                 # primary HttpClient (first logged-in user, else anonymous)
    crawl: object                  # CrawlResult of the primary client
    crawls: dict                   # session label -> CrawlResult (all crawled sessions)
    log: object                    # ResponseLog shared by all clients
    active_tests_allowed: bool     # may the scanner submit state-changing forms?
    progress: Callable = field(default=lambda msg: None)
    notes: list = field(default_factory=list)  # informational messages for the report


class DetectionModule:
    """Base class: every module has a key, a display name and ``run(ctx) -> list[Finding]``."""

    key = ""
    name = ""

    def run(self, ctx):  # pragma: no cover - interface
        raise NotImplementedError


def send_point(client, point, value):
    """Send an injection point with ``value`` substituted for its parameter (other params unchanged)."""
    params = dict(point.params)
    params[point.param] = value
    return client.get(point.url, params=params)


def comparable_text(resp, payload=""):
    """Visible text of a response with the payload (raw, HTML-escaped and URL-encoded) removed."""
    if resp is None:
        return ""
    return visible_text(resp.text, remove=(payload, quote_plus(payload)) if payload else ())
