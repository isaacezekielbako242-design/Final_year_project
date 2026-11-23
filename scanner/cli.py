"""Command-line interface (an alternative to the web dashboard).

    python -m scanner.cli http://127.0.0.1:5001/ --authorized \
        --user1 alice:alice-pass-123 --user2 bob:bob-pass-456

Writes reports/scan_<id>.html and reports/scan_<id>.json.
"""

import argparse
import sys

import config

from .detection_engine import DISCLAIMER, AuthorizationError, ScanEngine
from .json_export import export_json
from .models import Credential, ScanConfig
from .report_generator import save_report
from .target_validation import TargetValidationError


def parse_credential(text, label):
    if not text:
        return None
    if ":" not in text:
        raise ValueError(f"Credential for {label} must be in the form username:password")
    user, password = text.split(":", 1)
    return Credential(user, password, label)


def build_config(url, authorized, user1=None, user2=None, login_url=None, max_pages=config.MAX_PAGES,
                 delay=config.REQUEST_DELAY, modules=None):
    creds = [c for c in (parse_credential(user1, "user_a"), parse_credential(user2, "user_b")) if c]
    cfg = ScanConfig(target_url=url, authorized=authorized, credentials=creds, login_url=login_url or None,
                     max_pages=max_pages, request_delay=delay)
    if modules:
        cfg.modules = modules
    return cfg


def run_scan(cfg, quiet=False):
    def progress(pct, stage, msg):
        if not quiet:
            print(f"\r[{pct:3d}%] {stage}: {msg[:90]:<90}", end="", file=sys.stderr, flush=True)

    result = ScanEngine(cfg, progress=progress).run()
    if not quiet:
        print(file=sys.stderr)
    result["report_html"] = save_report(result)
    result["report_json"] = export_json(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Educational web vulnerability scanner. " + DISCLAIMER)
    parser.add_argument("url", nargs="?", default=config.DEFAULT_TARGET_URL)
    parser.add_argument("--authorized", action="store_true",
                        help="confirm that you are authorised to test the target (required)")
    parser.add_argument("--user1", help="first test account, username:password")
    parser.add_argument("--user2", help="second test account, username:password (for access-control tests)")
    parser.add_argument("--login-url")
    parser.add_argument("--max-pages", type=int, default=config.MAX_PAGES)
    parser.add_argument("--delay", type=float, default=config.REQUEST_DELAY, help="seconds between requests")
    parser.add_argument("--modules", default="sqli,xss,csrf,bac,misconfig")
    args = parser.parse_args(argv)

    try:
        cfg = build_config(args.url, args.authorized, args.user1, args.user2, args.login_url, args.max_pages,
                           args.delay, [m.strip() for m in args.modules.split(",") if m.strip()])
        result = run_scan(cfg)
    except (AuthorizationError, TargetValidationError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    s = result["summary"]
    print(f"\nScan of {result['target']} finished in {result['duration_seconds']} s "
          f"({result['requests_sent']} requests).")
    print(f"Findings: {s['total']}  (High {s['by_severity']['High']}, Medium {s['by_severity']['Medium']}, "
          f"Low {s['by_severity']['Low']})")
    for f in result["findings"]:
        print(f"  {f['finding_id']}  {f['severity']:<6}  {f['category']:<34} {f['url']}  [{f['parameter'] or '-'}]")
    for n in result["notes"]:
        print(f"  note: {n}")
    print(f"\nHTML report: {result['report_html']}\nJSON export: {result['report_json']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
