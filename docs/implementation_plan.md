# Technical Implementation Plan and Design Notes

## 1. Source of the specification

The Chapter Three document (System Analysis and Design) was **not available** in the project folder when this
implementation was produced. The project was therefore built from `project_requiremtn.md`, which describes the
components, technologies, database tables, test cases, metrics and safeguards in detail. If Chapter Three differs
from that file, for example in table names, severity levels or diagrams, compare the two and adjust the code. Each
concern lives in its own module, so changes stay local.

## 2. Components

| Layer | Component | File(s) |
|---|---|---|
| Interface | Web dashboard, CLI | `app.py`, `templates/`, `static/`, `scanner/cli.py` |
| Target configuration & scope | URL validation, reachability, same-origin scope | `scanner/target_validation.py`, `config.py` |
| Transport | Scoped, rate-limited HTTP client with response log | `scanner/http_client.py` |
| Authentication | Login-form discovery, login, two-user sessions | `scanner/authentication.py` |
| Discovery | Crawler (pages, forms, parameters, auth-required pages) | `scanner/crawler.py`, `scanner/html_utils.py` |
| Detection | Five independent modules | `sql_injection.py`, `xss.py`, `csrf.py`, `broken_access_control.py`, `security_misconfiguration.py` |
| Orchestration | Detection engine | `scanner/detection_engine.py` |
| Results | De-duplication, severity, remediation | `scanner/results_processor.py` |
| Output | HTML report, JSON export | `scanner/report_generator.py`, `scanner/json_export.py` |
| Evaluation | Ground-truth register, metrics | `evaluation/ground_truth.json`, `scanner/evaluator.py` |
| Testbed | Flask app, DB init, vulnerable/patched routes | `testbed/` |

## 3. Data flow

```
User (dashboard / CLI)
  │  target URL + authorisation + 0–2 test accounts
  ▼
ScanEngine ──► validate URL ──► reachability check ──► Scope(target origin)
  │
  ├─► SessionManager: anonymous client + one client per account (separate cookie jars), login
  ├─► Crawler (primary account) ──► pages, forms, injection points, auth-required flags
  ├─► Crawler (second account)  ──► used only by the access-control module
  │
  ├─► SQLi ─┐
  ├─► XSS  ─┤   every request goes through HttpClient (scope check, delay, timeout, budget)
  ├─► BAC  ─┤   and is recorded in ResponseLog
  ├─► CSRF ─┤
  └─► Misconfiguration (analyses ResponseLog + own probes)
            ▼
      raw Findings (in memory) ──► results_processor (merge, severity, remediation, redact)
            ▼
      result dict ──► report_generator (HTML) + json_export (JSON) ──► reports/
            ▼
      evaluator (vs ground_truth.json) ──► TP/FP/FN, precision, recall, F1, coverage
```

## 4. Development stages followed

1. Analysis and plan (this document).
2. Testbed: schema and seeding, shared models, common routes, vulnerable and patched routes, templates.
3. Target validation, scope, HTTP client, authentication, crawler. Verified against both testbeds.
4. The five detection modules. Each was verified to fire on the vulnerable testbed and stay silent on the patched one.
5. Results processing, HTML report, JSON export, ground truth, evaluator.
6. Dashboard, CLI, the 75-test pytest suite, and end-to-end runs on ports 5001/5002/8000.

## 5. Contradictions, ambiguities and decisions

| Issue | Decision |
|---|---|
| **OWASP Juice Shop vs custom Flask testbed.** The chapter reportedly mentions Juice Shop, while the detailed design specifies a custom Flask/SQLite store with 11 specific cases. | The **custom Flask testbed is the primary implementation**. Juice Shop is a large Angular single-page app (Node.js) whose vulnerabilities are not mapped to this register, and it needs JavaScript execution to crawl properly. This scanner does not execute JavaScript. Juice Shop could be used as optional secondary evaluation, with the expectation that results will be much weaker. |
| Scanner technologies list Requests/BS4/Jinja2/JSON but the spec asks for a "modern interface". | The dashboard uses **Flask**, which the project already depends on for the testbed, plus plain HTML/CSS/JS. No extra frameworks are needed. |
| "Scanner itself does not require a separate database." | Findings stay in memory and are exported to JSON/HTML. Dashboard jobs are in-memory only. |
| Missing headers: one or three findings? | They are aggregated into **one** site-wide finding per issue type (headers, cookie, verbose errors). This matches the register's one entry per test case and avoids one finding per page. |
| TP counting when two findings match one entry | Each ground-truth entry is matched at most once. Extra matches are reported as *duplicates*, so precision and recall use the same units. |
| CSRF "reversible operations" | Forms are re-submitted with their **existing** values, so the profile is unchanged. Checkout is submitted with an empty cart, so no order is created. Active submission is limited to localhost targets. |
| Which inputs SQLi/XSS fuzz | GET parameters and GET forms. All five injection test cases are GET-based, and fuzzing POST forms such as add-to-cart would change state. |
| Session cookie `Secure` flag | Not required by the spec, and the testbed runs over HTTP. It is checked only for https targets. |
| Port 5000 | The dashboard uses 8000 because macOS reserves 5000 for AirPlay. |

## 6. How the testbed isolates the flaws

* All shared data access (`testbed/models.py`) is parameterised.
* `vulnerable_routes.py` and `patched_routes.py` define the **same endpoints**: `/search`, `/product`, `/cart`,
  `/checkout`, `/order`, `/profile/view`, `/profile/update`. Each deliberate flaw is tagged `VULN-xx`.
* XSS: the vulnerable route wraps user input in `Markup()`, while the shared templates use normal `{{ }}`
  auto-escaping.
* CSRF: one token mechanism (`security.py`). The vulnerable app exempts exactly two endpoints.
* Cookies and headers: configured in `testbed/app.py` and in the patched `after_request` hook.
* Errors: the vulnerable error handler renders the traceback. The patched one renders a generic page and logs the
  details.
