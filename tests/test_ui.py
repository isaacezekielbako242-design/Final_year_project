"""End-to-end test of the dashboard API: start a scan, poll, view report, download JSON, evaluate."""

import time

import app as scanner_app


def test_full_dashboard_flow(vulnerable_server):
    client = scanner_app.app.test_client()
    assert b"EduVulnScanner" in client.get("/").data

    resp = client.post("/api/scans", json={
        "target_url": vulnerable_server.url, "authorized": True,
        "user1_username": "alice", "user1_password": "alice-pass-123",
        "user2_username": "bob", "user2_password": "bob-pass-456",
        "max_pages": 60, "delay": 0,
    })
    assert resp.status_code == 202
    job_id = resp.get_json()["job_id"]

    deadline = time.time() + 120
    while time.time() < deadline:
        status = client.get(f"/api/scans/{job_id}").get_json()
        if status["status"] != "running":
            break
        time.sleep(0.3)
    assert status["status"] == "completed", status.get("error")
    assert status["percent"] == 100
    assert status["result"]["summary"]["total"] == len(status["result"]["findings"]) > 0

    report = client.get(f"/scans/{job_id}/report")
    assert report.status_code == 200 and b"Security Report" in report.data

    js = client.get(f"/scans/{job_id}/json")
    assert js.headers["Content-Disposition"].startswith("attachment")
    assert b"alice-pass-123" not in js.data

    ev = client.post(f"/api/scans/{job_id}/evaluate", json={"version": "vulnerable"}).get_json()
    assert ev["tp"] + ev["fn"] == 11


def test_half_filled_credentials_rejected(vulnerable_server):
    client = scanner_app.app.test_client()
    resp = client.post("/api/scans", json={"target_url": vulnerable_server.url, "authorized": True,
                                           "user1_username": "alice"})
    assert resp.status_code == 400


def test_unknown_scan_returns_404():
    client = scanner_app.app.test_client()
    assert client.get("/api/scans/doesnotexist").status_code == 404
    assert client.get("/scans/doesnotexist/report").status_code == 404
