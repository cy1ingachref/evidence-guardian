"""XSS (Cross-Site Scripting) detector.

Finds reflected input that reaches the response without proper encoding.
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
        self.client = client or httpx.Client(timeout=10.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        params = ["q", "search", "name", "comment", "message", "input",
                  "keyword", "query", "term", "value", "review", "feedback"]
        paths = ["/search", "/api/search", "/rest/products/search",
                 "/api/v1/search", "/", "/api/comments", "/api/feedback",
                 "/contact", "/api/Baskets/", "/rest/basket/"]

        for path in paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in params:
                finding = self._test_xss_get(target, url, param)
                if finding:
                    findings.append(finding)
                    break

        # POST-based XSS
        post_endpoints = [
            ("/api/Feedbacks/", {"comment": "test", "rating": 5, "captcha": 0}),
            ("/rest/products/reviews/", {"message": "test", "author": "test"}),
        ]

        for path, base_body in post_endpoints:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for field in ["comment", "message", "review", "feedback"]:
                if field in base_body:
                    finding = self._test_xss_post_json(target, url, field, base_body)
                    if finding:
                        findings.append(finding)

        return findings

    def _test_xss_get(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        baseline = self._get(url, {param: "baseline-test-12345"})
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            response = self._get(url, {param: payload})
            if response is None or response.status_code != 200:
                continue

            if payload in response.body and not self._is_safe_context(response.body, payload):
                if self._response_differs(baseline, response):
                    evidence = Evidence(
                        finding_id=_next_finding_id("XSS"),
                        title=f"Reflected XSS via GET {param}",
                        description=f"Parameter {param} at {url} reflects input without encoding. Payload: {repr(payload)}",
                        request=HttpRequest(method="GET", url=f"{url}?{param}={payload}"),
                        response=response,
                        proof_script=self._generate_get_poc(url, param, payload),
                        metadata={"payload": payload, "method": "GET"},
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.XSS,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter=param,
                        summary=f"Reflected XSS via GET {param}.",
                        confidence=0.85,
                        evidence=evidence,
                    )

        return None

    def _test_xss_post_json(self, target: ScanTarget, url: str, field: str, base_body: dict) -> Finding | None:
        baseline = self._post_json(url, base_body)
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            body = dict(base_body)
            body[field] = payload
            response = self._post_json(url, body)
            if response is None or response.status_code != 200:
                continue

            if payload in response.body and not self._is_safe_context(response.body, payload):
                if self._response_differs(baseline, response):
                    evidence = Evidence(
                        finding_id=_next_finding_id("XSS"),
                        title=f"Stored XSS via POST JSON field '{field}'",
                        description=f"Field '{field}' at {url} stores and reflects input. Payload: {repr(payload)}",
                        request=HttpRequest(method="POST", url=url, body=f'{{"{field}": "{payload}"}}'),
                        response=response,
                        proof_script=self._generate_post_json_poc(url, field, payload),
                        metadata={"payload": payload, "method": "POST_JSON", "field": field},
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.XSS,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter=field,
                        summary=f"Stored XSS via POST JSON field '{field}'.",
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

    def _post_json(self, url: str, json_data: dict) -> HttpResponse | None:
        try:
            start = time.time()
            resp = self.client.post(url, json=json_data)
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
        if baseline.status_code != probe.status_code:
            return True
        baseline_len = len(baseline.body)
        probe_len = len(probe.body)
        if baseline_len > 0:
            ratio = abs(probe_len - baseline_len) / baseline_len
            return ratio > 0.05
        return probe_len > 0

    @staticmethod
    def _is_safe_context(body: str, payload: str) -> bool:
        idx = body.find(payload)
        if idx == -1:
            return True
        before = body[:idx]
        in_textarea = before.rfind("<textarea") > before.rfind("</textarea>")
        in_pre = before.rfind("<pre") > before.rfind("</pre>")
        in_code = before.rfind("<code") > before.rfind("</code>")
        return in_textarea or in_pre or in_code

    @staticmethod
    def _generate_get_poc(url: str, param: str, payload: str) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""XSS PoC: GET ' + param + ' parameter."""',
            "import requests",
            "from urllib.parse import quote",
            "",
            "url = " + repr(url),
            "payload = " + repr(payload),
            'url = f"{url}?{param}=" + quote(payload)',
            "",
            "response = requests.get(url)",
            'if payload in response.text:',
            '    print("CONFIRMED: Payload reflected without encoding")',
            '    print(f"Response: {response.text[:300]}")',
            'else:',
            '    print("NOT CONFIRMED: Payload not found")',
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _generate_post_json_poc(url: str, field: str, payload: str) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""XSS PoC: POST JSON field ' + field + '."""',
            "import requests",
            "",
            "url = " + repr(url),
            "json_data = " + repr({field: payload}),
            "",
            "response = requests.post(url, json=json_data)",
            'if ' + repr(payload) + ' in response.text:',
            '    print("CONFIRMED: Payload stored and reflected")',
            '    print(f"Response: {response.text[:300]}")',
            'else:',
            '    print("NOT CONFIRMED")',
            "",
        ]
        return "\n".join(lines)