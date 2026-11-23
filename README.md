# EduVulnScanner — Design and Implementation of a Vulnerability Scanner for E-commerce Websites

A modular Python vulnerability scanner plus **ShopLab**, a controlled Flask/SQLite e-commerce testbed with a
deliberately **vulnerable** version and a **patched** control version.

The scanner crawls a target, finds pages, forms and parameters, and tests for five categories:

| # | Category | Module | Technique |
|---|----------|--------|-----------|
| 1 | SQL Injection | `scanner/sql_injection.py` | DB-error signatures + Boolean TRUE/FALSE response comparison against a baseline |
| 2 | Cross-Site Scripting | `scanner/xss.py` | Unique harmless marker; checks whether an injected tag is reflected **unencoded** (reflected XSS only) |
| 3 | CSRF | `scanner/csrf.py` | Finds state-changing forms, checks for anti-CSRF tokens, submits without/with forged token (local targets only) |
| 4 | Broken Access Control | `scanner/broken_access_control.py` | Two logged-in users; requests user A's resources with user B's session |
| 5 | Security Misconfiguration | `scanner/security_misconfiguration.py` | Missing CSP / X-Content-Type-Options / X-Frame-Options, cookie HttpOnly / SameSite, stack traces |

> ⚠️ **Authorised testing only.** Use this scanner only on systems you own or have written permission to test.
> The vulnerable testbed is intentionally insecure. It binds to 127.0.0.1 only, and you should never deploy it.

---

## 1. Requirements

* Python **3.10 or later** (developed and tested on Python 3.15)
* macOS, Linux or Windows
* Recommended: Visual Studio Code, Git, browser developer tools

## 2. Installation

```bash
cd "Vulnerability Scanner"
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Initialise the testbed databases

```bash
python -m testbed.database                 # creates and seeds both databases
python -m testbed.database --mode vulnerable   # or just one of them
```

This creates `testbed/instance/shoplab_vulnerable.db` and `shoplab_patched.db` with the five tables
(users, products, cart_items, orders, order_items), 12 sample products and two fictitious test accounts:

| Username | Password | Orders | user_id |
|----------|----------|--------|---------|
| `alice` | `alice-pass-123` | #1, #2 | 1 |
| `bob` | `bob-pass-456` | #3 | 2 |

Passwords are stored as PBKDF2-SHA256 hashes in **both** versions. Re-run the command at any time to reset the data.
For example, run it after a CSRF test has changed a profile.

## 4. Start the testbed

Use `--mode` to choose a version. Both versions can run at the same time:

```bash
python -m testbed.app --mode vulnerable      # http://127.0.0.1:5001
python -m testbed.app --mode patched         # http://127.0.0.1:5002
python -m testbed.app --mode patched --port 6000 --reset-db
```

You can also set the mode with `SHOPLAB_MODE=patched python -m testbed.app`. A coloured banner at the top of
every page shows which version is running.

Testbed features: registration, login/logout, product listing and category filter, product search, product
details, shopping cart, cart updates, checkout, order history, order details and customer profile (view and edit).

## 5. Start the scanner dashboard

```bash
python app.py                                # http://127.0.0.1:8000
```

> Port 5000 is avoided because macOS uses it for AirPlay. Use `SCANNER_PORT=9000 python app.py` to change the port.

On the dashboard:

1. Enter the target URL, or use *Quick select → Vulnerable testbed / Patched testbed*.
2. Enter two test accounts, or click **Fill in the ShopLab test accounts**.
3. Optionally open *Advanced options* to set the login URL, crawl limit, request delay and modules.
4. Tick the **authorisation confirmation** box. The Start button stays disabled until you do.
5. Click **Start vulnerability scan** and watch the progress bar.
6. Review the summary cards, the per-category chart and the results table (category, URL, parameter, severity,
   evidence). You can filter the table by severity.
7. Click **View full HTML report** or **Download JSON**.
8. Under *Evaluate against the ground truth*, choose which testbed you scanned and click **Calculate metrics**.

Each finished scan is also saved as `reports/scan_<id>.html` and `reports/scan_<id>.json`.

### Command-line alternative

```bash
python -m scanner.cli http://127.0.0.1:5001/ --authorized \
       --user1 alice:alice-pass-123 --user2 bob:bob-pass-456
```

Options: `--login-url`, `--max-pages`, `--delay`, `--modules sqli,xss,csrf,bac,misconfig`.
Without `--authorized` the scan is refused.

## 6. Evaluation against the ground truth

The register `evaluation/ground_truth.json` documents the 11 deliberate weaknesses (VULN-01 … VULN-11) with their
category, URL, parameter or function, description and expected evidence.

With both testbeds running:

```bash
python -m scanner.evaluator          # scans 5001 and 5002, then compares with the register
# or evaluate saved results without rescanning:
python -m scanner.evaluator --vulnerable-json reports/scan_A.json --patched-json reports/scan_B.json
```

The evaluator prints a summary and saves `evaluation/evaluation_results/evaluation_<time>.json` and `.md`. It reports:

* **TP**: a finding that matches a documented vulnerability. Each entry can be matched once; extra matches are
  counted as *duplicates*, not as new TPs.
* **FP**: a finding that matches nothing. On the **patched** testbed the expected register is empty, so every
  finding there is a false positive to examine.
* **FN**: a documented vulnerability that no finding matched.
* Precision = TP/(TP+FP), Recall = TP/(TP+FN), F1 = 2PR/(P+R), and coverage per category.
* A combined figure: TP and FN from the vulnerable run, FPs from both runs.

All metrics are computed from real scan output. Nothing is hard-coded.

## 7. Running the tests

```bash
python -m pytest            # 75 tests, about 15 seconds
python -m pytest -v tests/test_detection_modules.py
```

The tests start both testbed versions as real local HTTP servers, each on a temporary database. They cover:

| Requirement | Test file |
|---|---|
| Target URL validation, scope, reachability | `test_target_validation.py` |
| Authorisation required (engine, API) | `test_authorization.py` |
| Crawler pages/forms/parameters; two-account login; failed login | `test_crawler_and_auth.py` |
| Each detection module (positive on vulnerable, negative on patched) | `test_detection_modules.py` |
| Results processing, HTML report, JSON export, credential redaction | `test_reporting.py` |
| Vulnerable testbed exposes all 11 cases; patched corrects them | `test_testbed.py` |
| Metric formulas, ground-truth register, real-scan evaluation | `test_evaluator.py` |
| Unavailable sites, malformed HTML, 500/404 pages, request budget | `test_error_handling.py` |
| Dashboard end-to-end (start, poll, report, JSON, evaluate) | `test_ui.py` |

## 8. Project structure

```
app.py                      scanner web dashboard (Flask)
config.py                   defaults: timeouts, delay, crawl limits, ports, paths
scanner/
  target_validation.py      URL validation, reachability, Scope (same scheme+host+port)
  http_client.py            scope-enforcing, rate-limited client; records every response
  authentication.py         login-form discovery, login, per-user SessionManager
  crawler.py                BFS crawler: pages, links, forms, parameters, auth-required pages
  html_utils.py             BeautifulSoup parsing, text similarity, evidence snippets
  base.py                   DetectionContext shared by the modules
  sql_injection.py  xss.py  csrf.py  broken_access_control.py  security_misconfiguration.py
  detection_engine.py       orchestrates a scan end-to-end
  results_processor.py      de-duplication, severity, remediation, summary
  report_generator.py       HTML report (Jinja2) - templates/report.html
  json_export.py            JSON export
  evaluator.py              ground-truth comparison and metrics (+ CLI)
  cli.py                    command-line scanner
templates/, static/         dashboard HTML/CSS/JS
testbed/
  app.py                    application factory and --mode switch
  database.py               schema, seeding, reset
  models.py                 parameterised data-access functions (shared)
  security.py               login_required, CSRF token, security headers
  common_routes.py          routes identical in both versions
  vulnerable_routes.py      the deliberate flaws, each tagged VULN-xx
  patched_routes.py         the same routes with fixes
  templates/, static/
evaluation/ground_truth.json, evaluation/evaluation_results/
reports/                    generated scan reports
tests/                      pytest suite
docs/implementation_plan.md design analysis, data flow, decisions and limitations
```

## 9. Safety features

* An authorisation checkbox (or `--authorized`) is required before every scan, and the API refuses scans without it.
* Every request, including each redirect hop, is checked against the target's scheme, host and port. External
  links are never followed.
* Timeouts (10 s), a global delay between requests (0.05 s by default), a cap of 3000 requests per scan, and a
  crawl limit.
* Testing is non-destructive. SQL payloads are read-only conditions, and there is no UNION, data extraction or
  stacked query. XSS probes use an inert, made-up tag. Injection tests use GET parameters only. Logout and delete
  links are never followed.
* CSRF verification submits forms **only against local hosts** and re-sends the original values. For other hosts
  it only checks whether a token is present (reported as *Tentative*).
* Credentials stay in memory only. They are cleared after the scan, usernames are masked in reports, and any
  password found in evidence is redacted.
* The testbed binds to 127.0.0.1, never runs the Werkzeug debugger, and contains only fictitious data.

## 10. Limitations

* XSS detection covers **reflected** XSS in GET parameters. It does not claim to detect stored or DOM-based XSS.
* SQL injection detection is error-based and Boolean-based only. Time-based blind and out-of-band techniques are
  not implemented.
* POST forms are not fuzzed for SQLi/XSS, to avoid state changes. They are tested by the CSRF module only.
* Access-control testing needs two working accounts and only covers ID-bearing resources linked from each user's
  own pages.
* The crawler does not execute JavaScript, so links built only by client-side scripts are not discovered.
* The perfect scores on ShopLab are expected, because the scanner and testbed were built together from the same
  specification. They show that the implemented checks work as designed. They do **not** predict performance on
  arbitrary real-world sites. For an external comparison, a public benchmark such as OWASP Juice Shop or DVWA
  could be scanned locally as additional, secondary evaluation.
