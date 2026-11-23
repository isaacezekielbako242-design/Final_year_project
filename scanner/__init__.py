"""EduVulnScanner - an educational web vulnerability scanner for e-commerce sites.

FOR AUTHORISED SECURITY TESTING ONLY.

Modules
-------
target_validation       URL validation, reachability and scope control
http_client             scope-enforcing, rate-limited HTTP client
authentication          login and per-user session management
crawler                 page / form / parameter discovery
sql_injection, xss, csrf, broken_access_control, security_misconfiguration
                        the five independent detection modules
detection_engine        orchestration of a complete scan
results_processor       de-duplication, severity, remediation, summary
report_generator        HTML report (Jinja2)
json_export             JSON export
evaluator               ground-truth comparison and metrics
cli                     command-line interface
"""

__version__ = "1.0.0"
