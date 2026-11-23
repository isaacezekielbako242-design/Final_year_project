"""Evaluation metrics are calculated correctly from findings and the ground truth."""

import pytest

from scanner.evaluator import combined_evaluation, evaluate, evaluate_scan, f1_score, load_ground_truth

GT = [
    {"id": "G1", "category": "SQL Injection", "url": "/search", "parameter": "q", "function": "f",
     "match": {"path": "/search", "parameter": "q"}},
    {"id": "G2", "category": "Broken Access Control", "url": "/order", "parameter": "id", "function": "f",
     "match": {"path": "/order", "parameter": "id"}},
    {"id": "G3", "category": "Security Misconfiguration", "url": "*", "parameter": None, "function": "f",
     "match": {"check": "verbose_errors"}},
]


def F(fid, cat, url, param=None, check=""):
    return {"finding_id": fid, "category": cat, "url": url, "parameter": param, "check": check,
            "title": "t", "evidence": "e"}


def test_metrics_formula():
    findings = [F("F1", "SQL Injection", "http://h/search", "q", "error_based+boolean_based"),
                F("F2", "SQL Injection", "http://h/search", "q", "x"),           # duplicate of G1
                F("F3", "Security Misconfiguration", "http://h/", None, "verbose_errors"),
                F("F4", "SQL Injection", "http://h/products", "category")]        # FP
    ev = evaluate(findings, GT)
    assert (ev["tp"], ev["fp"], ev["fn"], ev["duplicates"]) == (2, 1, 1, 1)
    assert ev["precision"] == pytest.approx(2 / 3)
    assert ev["recall"] == pytest.approx(2 / 3)
    assert ev["f1"] == pytest.approx(2 / 3)
    assert ev["coverage_by_category"]["Broken Access Control"]["coverage"] == 0
    assert ev["false_negatives"][0]["ground_truth_id"] == "G2"


def test_category_must_match():
    ev = evaluate([F("F1", "Cross-Site Scripting (XSS)", "http://h/search", "q")], GT)
    assert ev["tp"] == 0 and ev["fp"] == 1


def test_edge_cases():
    assert f1_score(None, 1.0) is None and f1_score(0.0, 0.0) == 0.0
    empty = evaluate([], [])
    assert empty["precision"] is None and empty["recall"] is None


def test_ground_truth_register_is_complete():
    gt = load_ground_truth()
    assert len(gt) == 11 and len({g["id"] for g in gt}) == 11
    for g in gt:
        assert {"id", "category", "url", "parameter", "function", "description", "expected_evidence", "match"} <= set(g)


def test_real_scan_evaluation(vulnerable_scan, patched_scan):
    """Metrics computed from actual scans of both testbeds (not hard-coded)."""
    v = evaluate_scan(vulnerable_scan, "vulnerable")
    p = evaluate_scan(patched_scan, "patched")
    assert v["tp"] + v["fn"] == 11
    assert v["tp"] == len(v["true_positives"])
    assert p["documented_vulnerabilities"] == 0 and p["fp"] == len(patched_scan["findings"])
    combined = combined_evaluation(v, p)
    assert combined["fp"] == v["fp"] + p["fp"]
    # The scanner is expected to find every documented case in this controlled testbed.
    assert v["recall"] == 1.0
