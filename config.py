"""Central configuration for the vulnerability scanner and its web interface.

Values can be overridden per scan from the dashboard / CLI; these are the defaults.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Scanner web interface -------------------------------------------------
# Port 5000 is avoided because macOS uses it for AirPlay Receiver.
SCANNER_HOST = "127.0.0.1"
SCANNER_PORT = int(os.environ.get("SCANNER_PORT", 8000))

# --- Default targets (the local controlled testbed) -------------------------
DEFAULT_TARGET_URL = "http://127.0.0.1:5001/"   # vulnerable testbed
PATCHED_TARGET_URL = "http://127.0.0.1:5002/"   # patched testbed

# --- HTTP behaviour / safety limits ------------------------------------------
REQUEST_TIMEOUT = 10          # seconds per request
REQUEST_DELAY = 0.05          # seconds between requests (rate limit)
MAX_REQUESTS = 3000           # hard cap on requests per scan
MAX_REDIRECTS = 5
USER_AGENT = "EduVulnScanner/1.0 (authorized-testing-only)"
MAX_BODY_CHARS = 200_000      # longest response body kept for analysis

# --- Crawler -------------------------------------------------------------------
MAX_PAGES = 60                # configurable crawl limit
MAX_DEPTH = 4
MAX_VARIANTS_PER_ENDPOINT = 5  # e.g. at most 5 different /product?id=... pages
# Links that must never be followed automatically (would end the session or destroy data).
EXCLUDED_LINK_PATTERNS = [r"logout", r"log-out", r"signout", r"sign-out", r"delete", r"remove", r"destroy"]

# --- Active (state-changing) tests -------------------------------------------
# CSRF verification submits forms. To avoid unauthorised state changes, this is
# only done automatically against local hosts; for other hosts the CSRF module
# performs passive token-presence checks only.
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
ACTIVE_TESTS_LOCAL_ONLY = True

# --- Output ------------------------------------------------------------------
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
GROUND_TRUTH_FILE = os.path.join(BASE_DIR, "evaluation", "ground_truth.json")
EVALUATION_RESULTS_DIR = os.path.join(BASE_DIR, "evaluation", "evaluation_results")
