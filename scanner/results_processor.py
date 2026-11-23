"""Results processing: de-duplication, severity rating, remediation and summary.

Findings from all five modules are collected in memory during the scan and
processed here before reporting:
  * duplicates (same category + URL + parameter [+ check for misconfigurations])
    are merged, keeping all evidence;
  * each finding receives a High / Medium / Low severity from SEVERITY_RULES;
  * a short remediation recommendation is attached;
  * any supplied password that might appear in the evidence is redacted;
  * findings are sorted by severity and category and numbered.
"""

from collections import Counter, OrderedDict
from urllib.parse import urlparse

from .models import BAC, CATEGORIES, CSRF, MISCONFIG, SEVERITIES, SQLI, XSS

# (category, check) -> severity; (category, None) is the category default.
SEVERITY_RULES = {
    (SQLI, None): "High",
    (XSS, None): "High",
    (BAC, None): "High",
    (CSRF, None): "Medium",
    (CSRF, "missing_token_passive"): "Low",
    (MISCONFIG, None): "Low",
    (MISCONFIG, "insecure_session_cookie"): "Medium",
    (MISCONFIG, "verbose_errors"): "Medium",
    (MISCONFIG, "missing_security_headers"): "Low",
}

REMEDIATION = {
    SQLI: "Use parameterised queries / prepared statements for every database call, validate input types "
          "(e.g. integers for IDs) and run the database account with least privilege.",
    XSS: "HTML-encode all user-supplied data on output (keep template auto-escaping on and never mark user input "
         "as safe), validate input, and add a restrictive Content-Security-Policy.",
    CSRF: "Require an unpredictable, per-session anti-CSRF token on every state-changing request and validate it "
          "server-side; set SameSite=Lax/Strict on session cookies.",
    BAC: "Enforce ownership checks on the server for every object access (e.g. WHERE order_id = ? AND user_id = ?) "
         "and return 403/404 for resources the user does not own.",
    MISCONFIG: "Harden the server configuration.",
}
MISCONFIG_REMEDIATION = {
    "missing_security_headers": "Send Content-Security-Policy, X-Content-Type-Options: nosniff and "
                                "X-Frame-Options: DENY (or CSP frame-ancestors) on every response.",
    "insecure_session_cookie": "Issue session cookies with HttpOnly, SameSite=Lax (or Strict) and, over HTTPS, Secure.",
    "verbose_errors": "Disable debug output in production, show generic error pages and log technical details "
                      "server-side only.",
}
CONFIDENCE_ORDER = {"Confirmed": 0, "Firm": 1, "Tentative": 2}


def _base_check(finding):
    """Merged findings may carry several checks, e.g. 'error_based+boolean_based'."""
    return (finding.check or "").split("+")[0] or None


def assign_severity(finding):
    rule = SEVERITY_RULES.get((finding.category, _base_check(finding)))
    return rule or SEVERITY_RULES.get((finding.category, None), "Medium")


def remediation_for(finding):
    if finding.category == MISCONFIG:
        return MISCONFIG_REMEDIATION.get(_base_check(finding), REMEDIATION[MISCONFIG])
    return REMEDIATION.get(finding.category, "")


def dedup_key(finding):
    path = urlparse(finding.url).path or "/"
    key = (finding.category, path, finding.parameter or "")
    if finding.category == MISCONFIG:
        key += (finding.check,)
    return key


def _redact(text, secrets):
    if not text:
        return text
    for s in secrets:
        if s and len(s) >= 3:
            text = text.replace(s, "[REDACTED]")
    return text


def process_findings(raw_findings, secrets=()):
    merged = OrderedDict()
    for f in raw_findings:
        key = dedup_key(f)
        if key not in merged:
            merged[key] = f
            continue
        existing = merged[key]
        if f.check and f.check not in existing.check.split("+"):
            existing.check = f"{existing.check}+{f.check}"
            existing.title = existing.title.split(" (")[0] + " (" + ", ".join(
                c.replace("_", "-") for c in existing.check.split("+")) + ")"
        if f.evidence and f.evidence not in existing.evidence:
            existing.evidence += "\n\n" + f.evidence
        if f.test_input and f.test_input not in (existing.test_input or ""):
            existing.test_input = f"{existing.test_input} | {f.test_input}" if existing.test_input else f.test_input
        if CONFIDENCE_ORDER.get(f.confidence, 9) < CONFIDENCE_ORDER.get(existing.confidence, 9):
            existing.confidence = f.confidence

    findings = list(merged.values())
    for f in findings:
        f.severity = assign_severity(f)
        f.remediation = remediation_for(f)
        f.evidence = _redact(f.evidence, secrets)
        f.test_input = _redact(f.test_input, secrets)

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), CATEGORIES.index(f.category), f.url,
                                 f.parameter or ""))
    for i, f in enumerate(findings, 1):
        f.finding_id = f"F-{i:03d}"
    return findings


def summarise(findings):
    sev = Counter(f.severity for f in findings)
    cat = Counter(f.category for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "by_category": {c: cat.get(c, 0) for c in CATEGORIES},
    }


def group_by_category(findings):
    groups = OrderedDict((c, []) for c in CATEGORIES)
    for f in findings:
        groups.setdefault(f.category, []).append(f)
    return groups
