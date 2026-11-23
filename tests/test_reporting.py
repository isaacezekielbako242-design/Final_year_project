"""Results processing, HTML report and JSON export."""

import html as html_lib
import json
import re

from scanner.json_export import export_json, load_json, to_json
from scanner.models import SQLI, Finding
from scanner.report_generator import render_report, save_report
from scanner.results_processor import process_findings, summarise


def _f(**kw):
    base = dict(category=SQLI, title="SQL injection (error-based)", url="http://h/search", parameter="q",
                severity="", test_input="'", evidence="e1", check="error_based")
    base.update(kw)
    return Finding(**base)


def test_duplicates_are_merged_and_severity_assigned():
    out = process_findings([_f(), _f(check="boolean_based", evidence="e2", title="SQL injection (Boolean-based)"),
                            _f(url="http://h/product", parameter="id")])
    assert len(out) == 2
    merged = [f for f in out if f.parameter == "q"][0]
    assert merged.check == "error_based+boolean_based" and "e1" in merged.evidence and "e2" in merged.evidence
    assert all(f.severity == "High" and f.remediation for f in out)
    assert [f.finding_id for f in out] == ["F-001", "F-002"]
    assert summarise(out)["by_category"][SQLI] == 2


def test_passwords_are_redacted_from_evidence():
    out = process_findings([_f(evidence="login with secret-pass-999 worked")], secrets=["secret-pass-999"])
    assert "secret-pass-999" not in out[0].evidence and "[REDACTED]" in out[0].evidence


def test_html_report_contains_findings(vulnerable_scan):
    html = render_report(vulnerable_scan)
    assert vulnerable_scan["target"] in html
    assert "Total vulnerabilities" in html and "Remediation" in html
    for f in vulnerable_scan["findings"]:
        assert f["finding_id"] in html
    # Payloads in evidence are escaped - the report itself must not be injectable.
    xss = [f for f in vulnerable_scan["findings"] if f["category"].startswith("Cross-Site Scripting")]
    assert xss
    for f in xss:
        tag = re.search(r"<vsx\w+tag>", f["test_input"]).group(0)
        assert tag not in html and html_lib.escape(tag) in html


def test_report_never_contains_credentials(vulnerable_scan):
    blob = render_report(vulnerable_scan) + to_json(vulnerable_scan)
    assert "alice-pass-123" not in blob and "bob-pass-456" not in blob


def test_json_export_roundtrip(vulnerable_scan, tmp_path):
    path = export_json(vulnerable_scan, directory=str(tmp_path))
    data = load_json(path)
    assert data["summary"]["total"] == len(data["findings"]) == vulnerable_scan["summary"]["total"]
    required = {"category", "url", "parameter", "severity", "test_input", "evidence"}
    assert all(required <= set(f) for f in data["findings"])
    json.dumps(data)  # serialisable


def test_report_saved_to_disk(vulnerable_scan, tmp_path):
    path = save_report(vulnerable_scan, directory=str(tmp_path))
    assert open(path, encoding="utf-8").read().startswith("<!doctype html>")
