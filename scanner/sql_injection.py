"""SQL injection detection (error-based and Boolean-based), NON-DESTRUCTIVE.

For every GET parameter discovered by the crawler:

1. Baseline - the page is requested with its original value.
2. Error-based - quote/parenthesis characters are appended; the response is
   searched for recognisable database error messages that were NOT in the
   baseline.
3. Boolean-based - pairs of always-TRUE / always-FALSE conditions are
   appended (e.g. ``1 AND 1=1`` vs ``1 AND 1=2``). A finding is recorded only
   when (a) the two TRUE responses match each other, (b) the two FALSE
   responses match each other, and (c) TRUE and FALSE responses clearly
   differ. Two independent pairs make accidental differences unlikely.

Only read-only conditions are used: no UNION/data extraction, no stacked
queries, no INSERT/UPDATE/DELETE/DROP.
"""

import re

from .base import DetectionModule, comparable_text, send_point
from .html_utils import similarity, snippet
from .http_client import RequestBudgetExceeded
from .models import SQLI, Finding

DB_ERROR_PATTERNS = [
    r"sqlite3?\.\w*Error", r"SQLite(?:3)?(?:Exception| error)", r"unrecognized token:",
    r"near \"[^\"]{0,40}\": syntax error", r"incomplete input",
    r"You have an error in your SQL syntax", r"Warning:.{0,40}mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"PostgreSQL.{0,40}ERROR", r"pg_query\(\)", r"unterminated quoted string",
    r"ORA-\d{5}", r"quoted string not properly terminated", r"Unclosed quotation mark after the character string",
    r"Microsoft OLE DB Provider for SQL Server", r"ODBC SQL Server Driver", r"SQLSTATE\[\w+\]",
    r"syntax error at or near",
]
DB_ERROR_RE = re.compile("|".join(DB_ERROR_PATTERNS), re.I)

ERROR_PAYLOADS = ["'", "')", "\"", "'\")", "`"]

# Each family: (TRUE-1, FALSE-1, TRUE-2, FALSE-2) appended to the original value.
STRING_FAMILIES = [
    ("' AND '1'='1", "' AND '1'='2", "' AND 'a'='a", "' AND 'a'='b"),
    ("' AND 1=1-- ", "' AND 1=2-- ", "' AND 2=2-- ", "' AND 2=3-- "),
    ("%' AND 1=1-- ", "%' AND 1=2-- ", "%' AND 2=2-- ", "%' AND 2=3-- "),
]
NUMERIC_FAMILIES = [
    (" AND 1=1", " AND 1=2", " AND 2=2", " AND 2=3"),
    (" AND 1=1-- ", " AND 1=2-- ", " AND 2=2-- ", " AND 2=3-- "),
]

SAME_THRESHOLD = 0.97     # TRUE-1 vs TRUE-2 (and FALSE-1 vs FALSE-2) must be at least this similar
DIFFERENT_THRESHOLD = 0.90  # TRUE vs FALSE must be less similar than this (or differ in status)


def find_db_error(text):
    m = DB_ERROR_RE.search(text or "")
    return m.group(0) if m else None


class SQLInjectionModule(DetectionModule):
    key = "sqli"
    name = SQLI

    def run(self, ctx):
        findings = []
        for point in ctx.crawl.injection_points:
            ctx.progress(f"SQLi: testing {point.url} [{point.param}]")
            try:
                findings.extend(self.test_point(ctx.client, point))
            except RequestBudgetExceeded:
                raise
            except Exception as exc:  # one bad page must not stop the module
                ctx.notes.append(f"SQLi test error on {point.url} [{point.param}]: {exc}")
        return findings

    def test_point(self, client, point):
        findings = []
        original = point.params.get(point.param, "")
        baseline = send_point(client, point, original)
        if baseline is None:
            return findings
        baseline_error = find_db_error(baseline.text)

        # --- 1. Error-based -------------------------------------------------
        for payload in ERROR_PAYLOADS:
            value = original + payload
            resp = send_point(client, point, value)
            if resp is None:
                continue
            error = find_db_error(resp.text)
            if error and not baseline_error:
                findings.append(Finding(
                    category=SQLI, title="SQL injection (error-based)", url=point.url,
                    parameter=point.param, severity="", test_input=value, check="error_based",
                    confidence="Firm",
                    evidence=(f"Appending {payload!r} produced a database error (HTTP {resp.status_code}) "
                              f"that is absent from the baseline response (HTTP {baseline.status_code}). "
                              f"Matched: \"{error}\". Context: {snippet(resp.text, error, 100)}"),
                    description="User input is placed into an SQL statement without proper parameterisation; "
                                "special characters break the query syntax.",
                ))
                break

        # --- 2. Boolean-based -----------------------------------------------
        families = list(STRING_FAMILIES)
        if re.fullmatch(r"-?\d+", original or ""):
            families = NUMERIC_FAMILIES + families
        for fam in families:
            result = self._boolean_test(client, point, original, fam)
            if result:
                findings.append(result)
                break
        return findings

    def _boolean_test(self, client, point, original, family):
        responses = []
        for suffix in family:
            resp = send_point(client, point, original + suffix)
            if resp is None:
                return None
            responses.append((original + suffix, resp))
        (t1v, t1), (f1v, f1), (t2v, t2), (f2v, f2) = responses

        # A TRUE condition must give a normal (non-error) page.
        if t1.status_code >= 500 or find_db_error(t1.text):
            return None
        t1_txt, f1_txt = comparable_text(t1, t1v), comparable_text(f1, f1v)
        t2_txt, f2_txt = comparable_text(t2, t2v), comparable_text(f2, f2v)

        true_consistent = t1.status_code == t2.status_code and similarity(t1_txt, t2_txt) >= SAME_THRESHOLD
        false_consistent = f1.status_code == f2.status_code and similarity(f1_txt, f2_txt) >= SAME_THRESHOLD
        tf_similarity = similarity(t1_txt, f1_txt)
        differs = t1.status_code != f1.status_code or tf_similarity < DIFFERENT_THRESHOLD
        if not (true_consistent and false_consistent and differs):
            return None
        return Finding(
            category=SQLI, title="SQL injection (Boolean-based)", url=point.url, parameter=point.param,
            severity="", test_input=f"TRUE: {t1v!r} / FALSE: {f1v!r}", check="boolean_based",
            confidence="Firm",
            evidence=(f"TRUE condition {t1v!r} -> HTTP {t1.status_code}, {len(t1_txt)} chars of text; "
                      f"FALSE condition {f1v!r} -> HTTP {f1.status_code}, {len(f1_txt)} chars. "
                      f"TRUE/FALSE similarity {tf_similarity:.0%}. Confirmed with a second pair "
                      f"({t2v!r} vs {f2v!r}). The application's output depends on injected SQL logic."),
            description="The response changes according to an injected Boolean condition, showing that the "
                        "input is interpreted as part of an SQL query.",
        )
