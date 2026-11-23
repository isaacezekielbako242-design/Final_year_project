"""Web interface (dashboard) for the vulnerability scanner.

    python app.py            ->  http://127.0.0.1:8000

Scans run in a background thread; the browser polls /api/scans/<id> for
progress. Results are kept in memory (no scanner database) and exported to
reports/ as HTML and JSON when each scan finishes.
"""

import threading
import uuid
from datetime import datetime

from flask import Flask, Response, abort, jsonify, render_template, request

import config
from scanner.detection_engine import DISCLAIMER, AuthorizationError, ScanEngine
from scanner.evaluator import evaluate_scan, render_markdown, save_evaluation
from scanner.json_export import export_json, to_json
from scanner.models import Credential, ScanConfig
from scanner.report_generator import render_report, save_report
from scanner.target_validation import TargetValidationError, validate_target_url

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

JOBS = {}            # job_id -> dict (in-memory only)
JOBS_LOCK = threading.Lock()
VALID_MODULES = {"sqli", "xss", "csrf", "bac", "misconfig"}


def _job_public(job, include_result=True):
    data = {k: job[k] for k in ("id", "status", "percent", "stage", "message", "target", "created", "error")}
    data["log"] = job["log"][-12:]
    if include_result and job.get("result"):
        r = job["result"]
        data["result"] = {k: r[k] for k in ("scan_id", "target", "started_at", "finished_at", "duration_seconds",
                                            "summary", "findings", "notes", "sessions", "crawl", "requests_sent",
                                            "limitations", "modules")}
    return data


def _run_job(job_id, cfg):
    job = JOBS[job_id]

    def progress(pct, stage, msg):
        job["percent"], job["stage"] = pct, stage
        if msg:
            job["message"] = msg
            job["log"].append(msg)
            del job["log"][:-200]

    try:
        result = ScanEngine(cfg, progress=progress).run()
        result["report_html"] = save_report(result)
        result["report_json"] = export_json(result)
        job["result"] = result
        job["status"] = "completed"
        job["message"] = f"Scan completed: {result['summary']['total']} finding(s)."
    except (AuthorizationError, TargetValidationError) as exc:
        job["status"], job["error"] = "failed", str(exc)
    except Exception as exc:  # never leave the UI waiting forever
        app.logger.exception("Scan failed")
        job["status"], job["error"] = "failed", f"Unexpected error: {type(exc).__name__}: {exc}"
    finally:
        for c in cfg.credentials:  # drop passwords from memory as soon as the scan ends
            c.password = ""
        job["percent"] = 100 if job["status"] == "completed" else job["percent"]


@app.route("/")
def dashboard():
    return render_template("index.html", disclaimer=DISCLAIMER, default_target=config.DEFAULT_TARGET_URL,
                           patched_target=config.PATCHED_TARGET_URL, max_pages=config.MAX_PAGES,
                           delay=config.REQUEST_DELAY)


@app.post("/api/scans")
def start_scan():
    # JSON only: a cross-site HTML form cannot send application/json, which
    # protects this local dashboard against CSRF-triggered scans.
    if not request.is_json:
        return jsonify(error="Expected a JSON request."), 415
    data = request.get_json(silent=True) or {}

    if data.get("authorized") is not True:
        return jsonify(error="You must confirm that you are authorised to test this target."), 400
    try:
        target = validate_target_url(data.get("target_url", ""))
    except TargetValidationError as exc:
        return jsonify(error=str(exc)), 400

    creds = []
    for idx, label in ((1, "user_a"), (2, "user_b")):
        u = (data.get(f"user{idx}_username") or "").strip()
        p = data.get(f"user{idx}_password") or ""
        if u and p:
            creds.append(Credential(u, p, label))
        elif u or p:
            return jsonify(error=f"Test account {idx}: enter both a username and a password (or neither)."), 400

    try:
        max_pages = max(1, min(int(data.get("max_pages") or config.MAX_PAGES), 500))
        delay = max(0.0, min(float(data.get("delay") if data.get("delay") not in (None, "") else config.REQUEST_DELAY), 5.0))
    except (TypeError, ValueError):
        return jsonify(error="Max pages and delay must be numbers."), 400
    modules = [m for m in (data.get("modules") or list(VALID_MODULES)) if m in VALID_MODULES]
    if not modules:
        return jsonify(error="Select at least one detection module."), 400

    cfg = ScanConfig(target_url=target, authorized=True, credentials=creds,
                     login_url=(data.get("login_url") or "").strip() or None,
                     max_pages=max_pages, request_delay=delay, modules=modules)
    job_id = uuid.uuid4().hex[:12]
    with JOBS_LOCK:
        JOBS[job_id] = {"id": job_id, "status": "running", "percent": 0, "stage": "Starting", "message": "",
                        "target": target, "created": datetime.now().isoformat(timespec="seconds"),
                        "error": None, "log": [], "result": None}
    threading.Thread(target=_run_job, args=(job_id, cfg), daemon=True).start()
    return jsonify(job_id=job_id), 202


@app.get("/api/scans")
def list_scans():
    return jsonify([_job_public(j, include_result=False) | {"total": (j["result"] or {}).get("summary", {}).get("total")}
                    for j in JOBS.values()])


@app.get("/api/scans/<job_id>")
def scan_status(job_id):
    job = JOBS.get(job_id) or abort(404)
    return jsonify(_job_public(job))


def _completed(job_id):
    job = JOBS.get(job_id)
    if not job or not job.get("result"):
        abort(404)
    return job


@app.get("/scans/<job_id>/report")
def view_report(job_id):
    job = _completed(job_id)
    return Response(render_report(job["result"], job.get("evaluation")), mimetype="text/html")


@app.get("/scans/<job_id>/json")
def download_json(job_id):
    result = _completed(job_id)["result"]
    return Response(to_json(result), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=scan_{result['scan_id']}.json"})


@app.post("/api/scans/<job_id>/evaluate")
def evaluate(job_id):
    job = _completed(job_id)
    version = (request.get_json(silent=True) or {}).get("version", "vulnerable")
    if version not in ("vulnerable", "patched"):
        return jsonify(error="version must be 'vulnerable' or 'patched'"), 400
    ev = evaluate_scan(job["result"], version)
    job["evaluation"] = ev
    paths = save_evaluation({version: ev}, render_markdown(ev))
    return jsonify(ev | {"saved_to": paths})


@app.after_request
def security_headers(resp):
    # The scanner's own UI follows the practices it tests for.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    if resp.mimetype == "text/html" and request.path == "/":
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'")
    return resp


if __name__ == "__main__":
    print(f"Vulnerability scanner dashboard: http://{config.SCANNER_HOST}:{config.SCANNER_PORT}")
    print(DISCLAIMER)
    app.run(host=config.SCANNER_HOST, port=config.SCANNER_PORT, debug=False, threaded=True)
