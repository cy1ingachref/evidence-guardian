"""XSS (Cross-Site Scripting) detector.

Finds reflected input that reaches the response without proper encoding.

Detection strategy:
1. Send baseline request (parameter with benign value)
2. Send request with XSS payload
3. Only flag if payload appears in response AND response differs from baseline
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from ..core import (
    Evidence,
    Finding,
    HttpRequest,
    HttpResponse,
    ScanTarget,
    Severity,
    VulnType,
    _next_finding_id,
)


class XSSModule:
    """Detect reflected XSS by injecting payloads and checking response reflection."""

    name = "xss"
    description = "Reflected Cross-Site Scripting via unencoded input reflection"

    PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "'-alert(1)-'",
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        params = ["q", "search", "name", "comment", "message", "input",
                  "keyword", "query", "term", "value"]
        paths = ["/search", "/api/search", "/", "/api/comments",
                 "/api/feedback", "/contact", "/api/v1/search",
                 "/rest/products/search", "/rest/user/login"]

        for path in paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in params:
                finding = self._test_reflection(target, url, param)
                if finding:
                    findings.append(finding)
                    break

        return findings

    def _test_reflection(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        """Test if a parameter reflects payloads without encoding."""
        # Get baseline
        baseline = self._get(url, {param: "baseline-test-12345"})
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            response = self._get(url, {param: payload})
            if response is None or response.status_code != 200:
                continue

            # Check if payload appears unencoded in response
            if payload in response.body:
                # Verify it's not just in a safe context (e.g., inside a textarea)
                if not self._is_safe_context(response.body, payload):
                    # Verify response differs from baseline (anti-false-positive)
                    if self._response_differs(baseline, response):
                        evidence = Evidence(
                            finding_id=_next_finding_id("XSS"),
                            title=f"Reflected XSS via {param} parameter",
                            description=f"Parameter {param} at {url} reflects input without "
                                        f"HTML encoding. Payload: {payload}",
                            request=HttpRequest(method="GET", url=f"{url}?{param}={payload}"),
                            response=response,
                            proof_script=self._generate_poc_script(url, param, payload),
                            metadata={"payload": payload},
                        )
                        return Finding(
                            id=evidence.finding_id,
                            type=VulnType.XSS,
                            severity=Severity.MEDIUM,
                            endpoint=url,
                            parameter=param,
                            summary=f"Reflected XSS: {param} parameter does not encode HTML special characters.",
                            confidence=0.85,
                            evidence=evidence,
                        )

        return None

    def _get(self, url: str, params: dict[str, str]) -> HttpResponse | None:
        try:
            start = time.time()
            resp = self.client.get(url, params=params)
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:5000],
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    @staticmethod
    def _response_differs(baseline: HttpResponse, probe: HttpResponse) -> bool:
        """Check if response differs from baseline (anti-false-positive)."""
        if baseline.status_code != probe.status_code:
            return True
        
        # Simple length check
        baseline_len = len(baseline.body)
        probe_len = len(probe.body)
        if baseline_len > 0:
            ratio = abs(probe_len - baseline_len) / baseline_len
            return ratio > 0.05
        
        return probe_len > 0

    @staticmethod
    def _is_safe_context(body: str, payload: str) -> bool:
        """Check if the payload reflection is inside a safe HTML context."""
        idx = body.find(payload)
        if idx == -1:
            return True

        before = body[:idx]
        in_textarea = before.rfind("<textarea") > before.rfind("</textarea>")
        in_pre = before.rfind("<pre") > before.rfind("</pre>")
        in_code = before.rfind("<code") > before.rfind("</code>")

        return in_textarea or in_pre or in_code

    @staticmethod
    def _generate_poc_script(url: str, param: str, payload: str) -> str:
        return '\n'.join([
            '#!/usr/bin/env python3',
            '"""XSS PoC: Verify reflected payload in ' + param + ' parameter."""',
            'import requests',
            'from urllib.parse import quote',
            '',
            'payload = "' + payload + '"',
            'url = "' + url + '?' + param + '=" + quote(payload)',
            '',
            'response = requests.get(url)',
            'if payload in response.text:',
            '    print("CONFIRMED: Payload reflected without encoding")',
            '    print(f"Response snippet: {response.text[:300]}")',
            'else:',
            '    print("NOT CONFIRMED: Payload not found in response")\n',
        ])