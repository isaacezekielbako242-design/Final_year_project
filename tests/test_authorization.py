"""Authorisation confirmation is mandatory before every scan."""

import pytest

import app as scanner_app
from scanner.detection_engine import AuthorizationError, ScanEngine
from tests.conftest import make_config


def test_engine_refuses_without_authorization(vulnerable_server):
    with pytest.raises(AuthorizationError):
        ScanEngine(make_config(vulnerable_server.url, authorized=False)).run()


def test_api_refuses_without_authorization(vulnerable_server):
    client = scanner_app.app.test_client()
    resp = client.post("/api/scans", json={"target_url": vulnerable_server.url, "authorized": False})
    assert resp.status_code == 400
    assert "authorised" in resp.get_json()["error"]


def test_api_requires_json_body(vulnerable_server):
    client = scanner_app.app.test_client()
    resp = client.post("/api/scans", data={"target_url": vulnerable_server.url, "authorized": "true"})
    assert resp.status_code == 415


def test_api_rejects_invalid_url():
    client = scanner_app.app.test_client()
    resp = client.post("/api/scans", json={"target_url": "not-a-url", "authorized": True})
    assert resp.status_code == 400
