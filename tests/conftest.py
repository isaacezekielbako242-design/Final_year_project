"""Shared fixtures: both testbed versions running as real local HTTP servers.

Each server uses a fresh temporary SQLite database, so tests never touch the
databases in testbed/instance/.
"""

import os
import re
import threading

import pytest
from werkzeug.serving import make_server

from scanner.detection_engine import ScanEngine
from scanner.models import Credential, ScanConfig
from testbed.app import create_app
from testbed.database import init_db

ALICE = ("alice", "alice-pass-123")
BOB = ("bob", "bob-pass-456")


class LiveServer:
    def __init__(self, app):
        self.server = make_server("127.0.0.1", 0, app, threaded=True)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()


def _app(mode, tmp_path_factory):
    db = os.path.join(tmp_path_factory.mktemp(f"db_{mode}"), "shoplab.db")
    init_db(db)
    app = create_app(mode, database=db)
    app.logger.disabled = True
    return app


@pytest.fixture(scope="session")
def vulnerable_server(tmp_path_factory):
    with LiveServer(_app("vulnerable", tmp_path_factory)) as srv:
        yield srv


@pytest.fixture(scope="session")
def patched_server(tmp_path_factory):
    with LiveServer(_app("patched", tmp_path_factory)) as srv:
        yield srv


def make_config(url, authorized=True, users=(ALICE, BOB), **kw):
    creds = [Credential(u, p, label) for (u, p), label in zip(users, ("user_a", "user_b"))]
    return ScanConfig(target_url=url, authorized=authorized, credentials=creds, request_delay=0, timeout=5, **kw)


@pytest.fixture(scope="session")
def vulnerable_scan(vulnerable_server):
    """One complete authenticated scan of the vulnerable testbed (shared by many tests)."""
    return ScanEngine(make_config(vulnerable_server.url)).run()


@pytest.fixture(scope="session")
def patched_scan(patched_server):
    return ScanEngine(make_config(patched_server.url)).run()


@pytest.fixture
def vuln_client(tmp_path):
    db = str(tmp_path / "v.db"); init_db(db)
    return create_app("vulnerable", database=db).test_client()


@pytest.fixture
def patched_client(tmp_path):
    db = str(tmp_path / "p.db"); init_db(db)
    return create_app("patched", database=db).test_client()


def login_test_client(client, username, password):
    page = client.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="(\w+)"', page).group(1)
    return client.post("/login", data={"username": username, "password": password, "csrf_token": token})


def findings_of(result, category, path=None, parameter=None):
    from urllib.parse import urlparse
    out = [f for f in result["findings"] if f["category"] == category]
    if path is not None:
        out = [f for f in out if urlparse(f["url"]).path == path]
    if parameter is not None:
        out = [f for f in out if f["parameter"] == parameter]
    return out
