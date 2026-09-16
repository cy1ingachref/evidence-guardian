"""XSS (Cross-Site Scripting) detector.

Finds reflected input that reaches the response without proper encoding.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlencode

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

    # Payloads that should never appear verbatim in safe output
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

        # Common XSS-prone patterns
        params = ["q", "search", "name", "comment", "message", "input",
                  "keyword", "query", "term", "value"]
        paths = ["/search", "/api/search", "/", "/api/comments",
                 "/api/feedback", "/contact", "/api/v1/search"]

        for path in paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in params:
                finding = self._test_reflection(target, url, param)
                if finding:
                    findings.append(finding)
                    break  # Found XSS for this endpoint, move on

        return findings

    def _test_reflection(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        """Test if a parameter reflects payloads without encoding."""
        for payload in self.PAYLOADS:
            response = self._get(url, {param: payload})
            if response is None or response.status_code != 200:
                continue

            # Check if payload appears unencoded in response
            if payload in response.body:
                # Verify it's not just in a safe context (e.g., inside a textarea)
                if not self._is_safe_context(response.body, payload):
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
    def _is_safe_context(body: str, payload: str) -> bool:
        """Check if the payload reflection is inside a safe HTML context."""
        idx = body.find(payload)
        if idx == -1:
            return True  # Not found, so technically safe

        # Check if inside textarea, pre, or code block
        before = body[:idx]
        in_textarea = before.rfind("<textarea") > before.rfind("</textarea>")
        in_pre = before.rfind("<pre") > before.rfind("</pre>")
        in_code = before.rfind("<code") > before.rfind("</code>")

        return in_textarea or in_pre or in_code

    @staticmethod
    def _generate_poc_script(url: str, param: str, payload: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"XSS PoC: Verify reflected payload in {param} parameter.\"\"\"
import requests
from urllib.parse import quote

payload = "{payload}"
url = "{url}?{param}=" + quote(payload)

response = requests.get(url)
if payload in response.text:
    print("CONFIRMED: Payload reflected without encoding")
    print(f"Response snippet: {{response.text[:300]}}")
else:
    print("NOT CONFIRMED: Payload not found in response")
"""
