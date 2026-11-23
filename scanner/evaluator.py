"""Evaluation of scan results against the ground-truth register.

Definitions (as specified in the project requirements):
  TP - a reported finding that matches a documented vulnerability;
  FP - a reported finding that does not match any documented vulnerability;
  FN - a documented vulnerability that no finding matches.

  Precision = TP / (TP + FP)
  Recall    = TP / (TP + FN)
  F1        = 2 * Precision * Recall / (Precision + Recall)

Each ground-truth entry can be matched at most once. If two findings match the
same entry, the second is counted as a *duplicate* (it is neither a new TP nor
an FP) - so TP never exceeds the number of documented vulnerabilities.

For the PATCHED testbed the expected register is empty: every finding there is
counted as a false positive and must be examined manually.

Nothing here is hard-coded: the metrics are computed from the findings of an
actual scan and evaluation/ground_truth.json.

CLI:
    python -m scanner.evaluator                         # scans both local testbeds, then evaluates
    python -m scanner.evaluator --vulnerable-json reports/scan_X.json --patched-json reports/scan_Y.json
"""

import argparse
import json
import os
from datetime import datetime
from urllib.parse import urlparse

import config

from .models import CATEGORIES


def load_ground_truth(path=config.GROUND_TRUTH_FILE):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["vulnerabilities"]


def _path(url):
    p = urlparse(url).path or "/"
    return p.rstrip("/") or "/"


def matches(finding, entry):
    """True when a finding (dict) corresponds to a ground-truth entry (dict)."""
    if finding["category"] != entry["category"]:
        return False
    rule = entry.get("match", {})
    if "check" in rule:
        return rule["check"] in (finding.get("check") or "").split("+")
    if _path(finding["url"]) != _path(rule.get("path", entry.get("url", ""))):
        return False
    expected_param = rule.get("parameter")
    return expected_param is None or finding.get("parameter") == expected_param


def safe_div(a, b):
    return a / b if b else None


def f1_score(precision, recall):
    if precision is None or recall is None:
        return None
    if precision + recall == 0:
        return 0.0
    return 2 * precision * recall / (precision + recall)


def fmt(value):
    return "n/a" if value is None else f"{value:.2%}"


def evaluate(findings, ground_truth, version="vulnerable"):
    """Compare a list of finding dicts with ground-truth entries."""
    matched_ids, tp_rows, fp_rows, dup_rows = set(), [], [], []
    for f in findings:
        entry = next((g for g in ground_truth if matches(f, g)), None)
        if entry is None:
            fp_rows.append(f)
        elif entry["id"] in matched_ids:
            dup_rows.append({"finding": f, "ground_truth_id": entry["id"]})
        else:
            matched_ids.add(entry["id"])
            tp_rows.append({"finding": f, "ground_truth_id": entry["id"]})
    fn_rows = [g for g in ground_truth if g["id"] not in matched_ids]

    tp, fp, fn = len(tp_rows), len(fp_rows), len(fn_rows)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = f1_score(precision, recall)

    coverage = {}
    for cat in CATEGORIES:
        documented = [g for g in ground_truth if g["category"] == cat]
        detected = [g for g in documented if g["id"] in matched_ids]
        coverage[cat] = {
            "documented": len(documented),
            "detected": len(detected),
            "coverage": safe_div(len(detected), len(documented)),
            "coverage_display": fmt(safe_div(len(detected), len(documented))),
            "false_positives": sum(1 for f in fp_rows if f["category"] == cat),
        }

    return {
        "version": version,
        "documented_vulnerabilities": len(ground_truth),
        "reported_findings": len(findings),
        "tp": tp, "fp": fp, "fn": fn, "duplicates": len(dup_rows),
        "precision": precision, "recall": recall, "f1": f1,
        "precision_display": fmt(precision), "recall_display": fmt(recall), "f1_display": fmt(f1),
        "coverage_by_category": coverage,
        "true_positives": [{"ground_truth_id": r["ground_truth_id"], "finding_id": r["finding"]["finding_id"],
                            "category": r["finding"]["category"], "url": r["finding"]["url"],
                            "parameter": r["finding"]["parameter"]} for r in tp_rows],
        "false_positives": [{"finding_id": f["finding_id"], "category": f["category"], "url": f["url"],
                             "parameter": f["parameter"], "title": f["title"], "evidence": f["evidence"]}
                            for f in fp_rows],
        "false_negatives": [{"ground_truth_id": g["id"], "category": g["category"], "url": g["url"],
                             "parameter": g["parameter"], "function": g["function"]} for g in fn_rows],
        "duplicates_detail": [{"ground_truth_id": d["ground_truth_id"], "finding_id": d["finding"]["finding_id"]}
                              for d in dup_rows],
    }


def evaluate_scan(result, version, ground_truth=None):
    """version='vulnerable' uses the register; version='patched' expects no vulnerabilities."""
    gt = ground_truth if ground_truth is not None else load_ground_truth()
    expected = gt if version == "vulnerable" else []
    ev = evaluate(result["findings"], expected, version)
    ev["scan_id"] = result.get("scan_id")
    ev["target"] = result.get("target")
    return ev


def combined_evaluation(vulnerable_eval, patched_eval):
    """Overall metrics: TP/FN from the vulnerable run; FPs from both runs."""
    tp = vulnerable_eval["tp"]
    fn = vulnerable_eval["fn"]
    fp = vulnerable_eval["fp"] + patched_eval["fp"]
    precision, recall = safe_div(tp, tp + fp), safe_div(tp, tp + fn)
    f1 = f1_score(precision, recall)
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1,
            "precision_display": fmt(precision), "recall_display": fmt(recall), "f1_display": fmt(f1)}


def render_markdown(vuln_eval, patched_eval=None, combined=None):
    lines = [f"# Scanner evaluation ({datetime.now():%Y-%m-%d %H:%M})", ""]
    for ev in [vuln_eval] + ([patched_eval] if patched_eval else []):
        lines += [f"## {ev['version'].capitalize()} testbed — {ev.get('target', '')} (scan {ev.get('scan_id')})", "",
                  "| Metric | Value |", "|---|---|",
                  f"| Documented vulnerabilities | {ev['documented_vulnerabilities']} |",
                  f"| Reported findings | {ev['reported_findings']} |",
                  f"| True positives | {ev['tp']} |", f"| False positives | {ev['fp']} |",
                  f"| False negatives | {ev['fn']} |", f"| Duplicates | {ev['duplicates']} |",
                  f"| Precision | {ev['precision_display']} |", f"| Recall | {ev['recall_display']} |",
                  f"| F1 score | {ev['f1_display']} |", ""]
        if ev["documented_vulnerabilities"]:
            lines += ["| Category | Documented | Detected | Coverage | FPs |", "|---|---|---|---|---|"]
            for cat, c in ev["coverage_by_category"].items():
                lines.append(f"| {cat} | {c['documented']} | {c['detected']} | {c['coverage_display']} | "
                             f"{c['false_positives']} |")
            lines.append("")
        if ev["true_positives"]:
            lines += ["**Matched:** " + ", ".join(f"{t['ground_truth_id']}←{t['finding_id']}"
                                                  for t in ev["true_positives"]), ""]
        if ev["false_negatives"]:
            lines += ["**Missed (FN):** " + ", ".join(f"{g['ground_truth_id']} ({g['function']})"
                                                     for g in ev["false_negatives"]), ""]
        if ev["false_positives"]:
            lines += ["**False positives to examine:**"] + [
                f"- {f['finding_id']} {f['category']} {f['url']} [{f['parameter']}] — {f['title']}"
                for f in ev["false_positives"]] + [""]
    if combined:
        lines += ["## Combined (TP/FN from vulnerable run, FP from both runs)", "",
                  f"Precision **{combined['precision_display']}**, Recall **{combined['recall_display']}**, "
                  f"F1 **{combined['f1_display']}** (TP={combined['tp']}, FP={combined['fp']}, FN={combined['fn']})", ""]
    return "\n".join(lines)


def save_evaluation(payload, markdown, directory=config.EVALUATION_RESULTS_DIR):
    os.makedirs(directory, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = os.path.join(directory, f"evaluation_{stamp}.json")
    md_path = os.path.join(directory, f"evaluation_{stamp}.md")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    return json_path, md_path


def main():
    from .cli import build_config, run_scan  # local import avoids a circular import
    from .json_export import load_json

    parser = argparse.ArgumentParser(description="Evaluate the scanner against the ShopLab ground truth.")
    parser.add_argument("--vulnerable-url", default=config.DEFAULT_TARGET_URL)
    parser.add_argument("--patched-url", default=config.PATCHED_TARGET_URL)
    parser.add_argument("--vulnerable-json", help="evaluate an existing JSON result instead of scanning")
    parser.add_argument("--patched-json", help="evaluate an existing JSON result instead of scanning")
    parser.add_argument("--user1", default="alice:alice-pass-123")
    parser.add_argument("--user2", default="bob:bob-pass-456")
    parser.add_argument("--skip-patched", action="store_true")
    args = parser.parse_args()

    def get_result(json_path, url):
        if json_path:
            return load_json(json_path)
        print(f"Scanning {url} ...")
        return run_scan(build_config(url, True, args.user1, args.user2))

    vuln_result = get_result(args.vulnerable_json, args.vulnerable_url)
    vuln_eval = evaluate_scan(vuln_result, "vulnerable")
    patched_eval = combined = None
    if not args.skip_patched:
        patched_result = get_result(args.patched_json, args.patched_url)
        patched_eval = evaluate_scan(patched_result, "patched")
        combined = combined_evaluation(vuln_eval, patched_eval)

    md = render_markdown(vuln_eval, patched_eval, combined)
    paths = save_evaluation({"vulnerable": vuln_eval, "patched": patched_eval, "combined": combined}, md)
    print(md)
    print(f"Saved: {paths[0]}\n       {paths[1]}")


if __name__ == "__main__":
    main()
