"""Detection engine - orchestrates a complete scan.

Pipeline (each stage reports progress through a callback):

    authorisation check -> URL validation -> reachability check
    -> login of test accounts -> crawl (primary session, then the second
       account for access-control testing) -> five detection modules
    -> results processing -> HTML report + JSON export

A failure inside one module is recorded in the scan notes and the scan carries on.
"""

import time
import uuid
from datetime import datetime

import config

from .authentication import SessionManager
from .base import DetectionContext
from .broken_access_control import BrokenAccessControlModule
from .crawler import Crawler
from .csrf import CSRFModule
from .http_client import RateLimiter, RequestBudgetExceeded, RequestCounter, ResponseLog
from .models import mask
from .results_processor import process_findings, summarise
from .security_misconfiguration import SecurityMisconfigurationModule
from .sql_injection import SQLInjectionModule
from .target_validation import Scope, TargetValidationError, check_reachable, is_local_host, validate_target_url
from .xss import XSSModule

# Order matters: read-only modules first, the CSRF module (which submits forms)
# next, and the misconfiguration module last because it inspects every response.
MODULES = [SQLInjectionModule, XSSModule, BrokenAccessControlModule, CSRFModule, SecurityMisconfigurationModule]

DISCLAIMER = ("This scanner is intended ONLY for authorised security testing of systems you own or have written "
              "permission to test. Default testing should use the local ShopLab testbed.")

LIMITATIONS = [
    "XSS checks cover reflected XSS in GET parameters only; stored and DOM-based XSS are not claimed to be detected.",
    "SQL injection checks are error-based and Boolean-based only (no time-based or out-of-band techniques, "
    "no data extraction).",
    "Injection tests are applied to URL parameters and GET forms; POST forms are not fuzzed to avoid state changes.",
    "CSRF verification submits forms only against local hosts; elsewhere only token presence is checked.",
    "Access-control testing requires two working test accounts and covers resources linked in each account's pages.",
]


class AuthorizationError(Exception):
    """Raised when a scan is started without the authorisation confirmation."""


class ScanEngine:
    def __init__(self, scan_config, progress=None):
        self.cfg = scan_config
        self._progress_cb = progress or (lambda pct, stage, msg: None)
        self.percent = 0
        self.stage = "Queued"

    def _progress(self, pct=None, stage=None, msg=""):
        if pct is not None:
            self.percent = pct
        if stage:
            self.stage = stage
        self._progress_cb(self.percent, self.stage, msg)

    def run(self):
        cfg = self.cfg
        started = datetime.now()
        t0 = time.monotonic()
        scan_id = started.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]

        # --- Safeguard: explicit authorisation is mandatory -----------------
        if not cfg.authorized:
            raise AuthorizationError("You must confirm that you are authorised to test this target.")

        self._progress(2, "Validating target")
        cfg.target_url = validate_target_url(cfg.target_url)
        check_reachable(cfg.target_url, timeout=cfg.timeout)  # raises TargetValidationError

        scope = Scope(cfg.target_url)
        log = ResponseLog()
        sessions = SessionManager(scope, log, RateLimiter(cfg.request_delay),
                                  RequestCounter(config.MAX_REQUESTS), cfg.timeout)
        notes = []

        # --- Authentication -------------------------------------------------
        self._progress(5, "Authenticating test accounts")
        sessions.authenticate_all(cfg.credentials, cfg.login_url)
        for s in sessions.sessions:
            notes.append(f"Login {s.label} ({mask(s.username)}): {'OK' if s.authenticated else 'FAILED'} - {s.message}")
        if cfg.credentials and not sessions.authenticated:
            notes.append("No test account could log in - continuing with an unauthenticated scan.")

        # --- Crawling ---------------------------------------------------------
        crawls = {}
        primary = sessions.primary_client()
        self._progress(10, "Crawling website")
        crawler = Crawler(primary, max_pages=cfg.max_pages, max_depth=cfg.max_depth,
                          progress=lambda m: self._progress(msg=m))
        # (the crawler handles request-budget exhaustion and unreachable pages itself)
        crawl = crawler.crawl(cfg.target_url)
        crawler.classify_authentication(crawl, sessions.anonymous)
        crawls[primary.label] = crawl
        if not crawl.pages:
            notes.append("The crawler could not retrieve any page from the target.")

        if "bac" in cfg.modules and len(sessions.authenticated) >= 2:
            for s in sessions.authenticated[1:]:
                self._progress(20, f"Crawling as {s.label}")
                c = Crawler(s.client, max_pages=cfg.max_pages, max_depth=cfg.max_depth,
                            progress=lambda m: self._progress(msg=m))
                crawls[s.label] = c.crawl(cfg.target_url)
                c.classify_authentication(crawls[s.label], sessions.anonymous)

        ctx = DetectionContext(
            scan_config=cfg, scope=scope, sessions=sessions, client=primary, crawl=crawl, crawls=crawls,
            log=log, notes=notes, progress=lambda m: self._progress(msg=m),
            active_tests_allowed=is_local_host(cfg.target_url) or not config.ACTIVE_TESTS_LOCAL_ONLY,
        )

        # --- Detection modules ------------------------------------------------
        raw_findings, module_status = [], {}
        enabled = [m() for m in MODULES if m.key in cfg.modules]
        for i, module in enumerate(enabled):
            self._progress(30 + int(60 * i / max(len(enabled), 1)), f"Running {module.name} checks")
            m_start = time.monotonic()
            try:
                found = module.run(ctx)
                raw_findings.extend(found)
                module_status[module.name] = {"status": "completed", "raw_findings": len(found)}
            except RequestBudgetExceeded as exc:
                module_status[module.name] = {"status": "stopped", "error": str(exc)}
                notes.append(f"{module.name}: stopped - {exc}")
            except Exception as exc:  # defensive: a module bug must not crash the scan
                module_status[module.name] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
                notes.append(f"{module.name} failed: {type(exc).__name__}: {exc}")
            module_status[module.name]["seconds"] = round(time.monotonic() - m_start, 2)

        # --- Results processing -----------------------------------------------
        self._progress(92, "Processing results")
        secrets = [c.password for c in cfg.credentials]
        findings = process_findings(raw_findings, secrets=secrets)

        finished = datetime.now()
        result = {
            "scan_id": scan_id,
            "scanner": "EduVulnScanner 1.0",
            "disclaimer": DISCLAIMER,
            "target": cfg.target_url,
            "started_at": started.isoformat(timespec="seconds"),
            "finished_at": finished.isoformat(timespec="seconds"),
            "duration_seconds": round(time.monotonic() - t0, 2),
            "configuration": cfg.public_dict(),
            "sessions": [{"label": s.label, "username": mask(s.username), "authenticated": s.authenticated,
                          "message": s.message} for s in sessions.sessions],
            "crawl": {label: c.summary() for label, c in crawls.items()},
            "discovered": {
                "pages": [{"url": p.url, "status": p.status, "requires_auth": p.requires_auth, "title": p.title}
                          for p in crawl.pages.values()],
                "forms": [{"page": f.page_url, "action": f.action, "method": f.method, "fields": f.field_names()}
                          for f in crawl.forms],
                "parameters": [{"url": p.url, "parameter": p.param, "source": p.source}
                               for p in crawl.injection_points],
            },
            "modules": module_status,
            "requests_sent": sessions.anonymous.counter.count,
            "network_errors": log.errors[:50],
            "out_of_scope_blocked": len(log.blocked),
            "summary": summarise(findings),
            "findings": [f.to_dict() for f in findings],
            "notes": notes,
            "limitations": LIMITATIONS,
        }
        self._progress(100, "Completed")
        return result


__all__ = ["ScanEngine", "AuthorizationError", "TargetValidationError", "DISCLAIMER"]
