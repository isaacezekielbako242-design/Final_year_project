"""JSON export of scan results.

Findings are kept in memory during the scan (the scanner has no database) and
written to ``reports/scan_<id>.json`` when the scan completes. The result
never contains passwords: ScanConfig.public_dict() omits them, usernames are
masked and the results processor redacts any password found in evidence.
"""

import json
import os

import config


def to_json(result, indent=2):
    return json.dumps(result, indent=indent, ensure_ascii=False, default=str)


def export_json(result, directory=config.REPORTS_DIR):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"scan_{result['scan_id']}.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(to_json(result))
    return path


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
