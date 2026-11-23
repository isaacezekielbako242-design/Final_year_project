"""Reflected Cross-Site Scripting (XSS) detection.

SCOPE: this module detects REFLECTED XSS only - input that is echoed back in
the immediate response without HTML encoding. It does NOT claim to detect
stored (persistent) XSS or DOM-based XSS, which need different techniques
(multi-step workflows and JavaScript execution in a browser respectively).

Method for each GET parameter:
1. Send a unique alphanumeric marker (e.g. ``vsx3fa9c1d2``) - is it reflected?
2. If reflected, send probes that contain a harmless, non-existent HTML tag
   built from the marker, e.g. ``vsx3fa9c1d2<vsx3fa9c1d2tag>``. No script is
   ever executed. If the tag appears in the response *unencoded*, the browser
   would parse attacker-controlled markup -> reflected XSS. If it appears as
   ``&lt;vsx…tag&gt;`` the output is properly encoded and nothing is reported.
"""

import secrets

from .base import DetectionModule, send_point
from .html_utils import snippet
from .http_client import RequestBudgetExceeded
from .models import XSS, Finding


def make_marker():
    return "vsx" + secrets.token_hex(4)


class XSSModule(DetectionModule):
    key = "xss"
    name = XSS

    def run(self, ctx):
        findings = []
        for point in ctx.crawl.injection_points:
            ctx.progress(f"XSS: testing {point.url} [{point.param}]")
            try:
                finding = self.test_point(ctx.client, point)
            except RequestBudgetExceeded:
                raise
            except Exception as exc:
                ctx.notes.append(f"XSS test error on {point.url} [{point.param}]: {exc}")
                continue
            if finding:
                findings.append(finding)
        return findings

    def test_point(self, client, point):
        marker = make_marker()
        resp = send_point(client, point, marker)
        if resp is None or marker not in resp.text:
            return None  # input is not reflected -> no reflected XSS possible here

        tag = f"<{marker}tag>"
        probes = [
            ("HTML element context", f"{marker}{tag}"),
            ("attribute breakout (double quote)", f'{marker}">{tag}'),
            ("attribute breakout (single quote)", f"{marker}'>{tag}"),
        ]
        for context, probe in probes:
            r = send_point(client, point, probe)
            if r is None:
                continue
            body = r.text
            if tag in body:
                return Finding(
                    category=XSS, title="Reflected cross-site scripting", url=point.url,
                    parameter=point.param, severity="", test_input=probe, check="reflected",
                    confidence="Firm",
                    evidence=(f"The marker {marker!r} is reflected, and the injected tag {tag} appears "
                              f"UNENCODED in the HTML response (HTTP {r.status_code}; {context}). "
                              f"Response excerpt: {snippet(body, tag, 90)}"),
                    description="Input is written into the page without HTML encoding, so an attacker-crafted "
                                "link could inject script that runs in the victim's browser.",
                )
        # Reflected but HTML-encoded (e.g. "&lt;vsx...tag&gt;") -> handled correctly, not reported.
        return None
