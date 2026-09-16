"""SQLi (SQL Injection) detector.

Tests input parameters for SQL error messages and time-based blind injection.

Detection strategy:
1. Get baseline (parameter with benign value)
2. Send SQLi payloads via GET, POST (form), and POST (JSON)
3. Flag only if response differs from baseline AND contains SQL errors
"""
from __future__ import annotations

import re
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


class SQLiModule:
    """Detect SQL injection via error-based and time-based techniques."""

    name = "sqli"
    description = "SQL Injection via unparameterized queries"

    ERROR_SIGNATURES = [
        r"sql syntax.*mysql",
        r"warning.*mysql_",
        r"unclosed quotation mark",
        r"ora-[0-9]{4,5}",
        r"postgresql.*error",
        r"sqlite.*error",
        r"sql error.*(syntax|near|no such column|unterminated)",
        r"microsoft sql server",
        r"odbc sql server driver",
        r"unterminated quoted string",
        r"you have an error in your sql syntax",
        r"syntax error.*(sql|query|database)",
    ]

    PAYLOADS = [
        "'",
        "\"",
        "' OR '1'='1",
        "1' AND '1'='1",
        "1' AND '1'='2",
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        # GET-based endpoints (search, query, etc.)
        get_params = ["q", "search", "query", "id", "user", "username", "email",
                      "name", "category", "product", "item"]
        get_paths = ["/api/search", "/api/products/search", "/api/v1/search",
                     "/rest/products/search", "/rest/user/login", "/search",
                     "/api/products", "/api/v1/products", "/api/login"]

        for path in get_paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in get_params:
                finding = self._test_sqli_get(target, url, param)
                if finding:
                    findings.append(finding)
                    break

        # POST-based endpoints (login, registration, feedback)
        post_form_endpoints = [
            ("/rest/user/login", {"email": "test@test.com", "password": "test"}),
            ("/api/Users/", {"email": "test@test.com", "password": "test", "passwordRepeat": "test"}),
            ("/rest/user/reset-password", {"email": "test@test.com"}),
            ("/api/Products/1", {"review": "test"}),
        ]

        for path, base_body in post_form_endpoints:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for field in base_body:
                finding = self._test_sqli_post_form(target, url, field, base_body)
                if finding:
                    findings.append(finding)

        # JSON-based endpoints
        json_endpoints = [
            ("/rest/user/login", {"email": "test@test.com", "password": "test"}),
            ("/rest/basket/1/checkout", {}),
            ("/api/Baskets/", {"ProductId": 1, "BasketId": 1, "quantity": 1}),
        ]

        for path, base_body in json_endpoints:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for field in base_body:
                finding = self._test_sqli_post_json(target, url, field, base_body)
                if finding:
                    findings.append(finding)

        return findings

    def _test_sqli_get(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        """Test a parameter via GET for SQL injection."""
        # Get baseline
        baseline = self._get(url, {param: "normal_value_123"})
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            response = self._get(url, {param: payload})
            if response is None:
                continue

            if self._has_sql_error(response) and self._response_differs(baseline, response):
                evidence = Evidence(
                    finding_id=_next_finding_id("SQLI"),
                    title=f"SQL Injection via GET {param}",
                    description=f"Payload '{payload}' triggered SQL error in {url} (GET).",
                    request=HttpRequest(method="GET", url=f"{url}?{param}={payload}"),
                    response=response,
                    proof_script=self._generate_get_poc(url, param, payload),
                    metadata={"payload": payload, "method": "GET", "type": "error-based"},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=param,
                    summary=f"SQL error triggered by GET {param} payload.",
                    confidence=0.92,
                    evidence=evidence,
                )

        return None

    def _test_sqli_post_form(self, target: ScanTarget, url: str, field: str, base_body: dict) -> Finding | None:
        """Test a form field via POST (application/x-www-form-urlencoded) for SQL injection."""
        # Get baseline
        baseline = self._post_form(url, base_body)
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            body = dict(base_body)
            body[field] = payload
            response = self._post_form(url, body)
            if response is None:
                continue

            if self._has_sql_error(response) and self._response_differs(baseline, response):
                evidence = Evidence(
                    finding_id=_next_finding_id("SQLI"),
                    title=f"SQL Injection via POST form field '{field}'",
                    description=f"Payload '{payload}' in field '{field}' triggered SQL error in {url}.",
                    request=HttpRequest(method="POST", url=url, body=f"{field}={payload}"),
                    response=response,
                    proof_script=self._generate_post_form_poc(url, field, payload),
                    metadata={"payload": payload, "method": "POST_FORM", "field": field, "type": "error-based"},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=field,
                    summary=f"SQL error triggered by POST form field '{field}'.",
                    confidence=0.92,
                    evidence=evidence,
                )

        return None

    def _test_sqli_post_json(self, target: ScanTarget, url: str, field: str, base_body: dict) -> Finding | None:
        """Test a JSON field via POST for SQL injection."""
        # Get baseline
        baseline = self._post_json(url, base_body)
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            body = dict(base_body)
            body[field] = payload
            response = self._post_json(url, body)
            if response is None:
                continue

            if self._has_sql_error(response) and self._response_differs(baseline, response):
                evidence = Evidence(
                    finding_id=_next_finding_id("SQLI"),
                    title=f"SQL Injection via POST JSON field '{field}'",
                    description=f"Payload '{payload}' in JSON field '{field}' triggered SQL error in {url}.",
                    request=HttpRequest(method="POST", url=url, body=f'{{"{field}": "{payload}"}}'),
                    response=response,
                    proof_script=self._generate_post_json_poc(url, field, payload),
                    metadata={"payload": payload, "method": "POST_JSON", "field": field, "type": "error-based"},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=field,
                    summary=f"SQL error triggered by POST JSON field '{field}'.",
                    confidence=0.92,
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
                body=resp.text[:3000],
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _post_form(self, url: str, data: dict[str, str]) -> HttpResponse | None:
        try:
            start = time.time()
            resp = self.client.post(url, data=data)
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:3000],
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
                body=resp.text[:3000],
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _has_sql_error(self, response: HttpResponse) -> bool:
        body_lower = response.body.lower()
        return any(re.search(sig, body_lower) for sig in self.ERROR_SIGNATURES)

    @staticmethod
    def _response_differs(baseline: HttpResponse, probe: HttpResponse) -> bool:
        """Check if response differs from baseline."""
        if baseline.status_code != probe.status_code:
            return True
        
        baseline_len = len(baseline.body)
        probe_len = len(probe.body)
        if baseline_len > 0:
            ratio = abs(probe_len - baseline_len) / baseline_len
            return ratio > 0.1
        
        return probe_len > 0

    @staticmethod
    def _is_time_based(baseline: HttpResponse, payload_response: HttpResponse) -> bool:
        """Check if payload caused a significant time delay."""
        time_diff = payload_response.response_time_ms - baseline.response_time_ms
        return time_diff > 4000

    @staticmethod
    def _generate_get_poc(url: str, param: str, payload: str) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""SQLi PoC: GET ' + param + ' parameter."""',
            "import requests",
            "",
            'url = "' + url + '"',
            'params = {"' + param + '": "' + payload + '"}',
            "",
            "response = requests.get(url, params=params)",
            'print(f"Status: {response.status_code}")',
            'print(f"Body: {response.text[:500]}")',
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _generate_post_form_poc(url: str, field: str, payload: str) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""SQLi PoC: POST form field ' + field + '."""',
            "import requests",
            "",
            'url = "' + url + '"',
            'data = {"' + field + '": "' + payload + '"}',
            "",
            "response = requests.post(url, data=data)",
            'print(f"Status: {response.status_code}")',
            'print(f"Body: {response.text[:500]}")',
            "",
        ]
        return "\n".join(lines)

    @staticmethod
    def _generate_post_json_poc(url: str, field: str, payload: str) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""SQLi PoC: POST JSON field ' + field + '."""',
            "import requests",
            "",
            'url = "' + url + '"',
            'json_data = {"' + field + '": "' + payload + '"}',
            "",
            "response = requests.post(url, json=json_data)",
            'print(f"Status: {response.status_code}")',
            'print(f"Body: {response.text[:500]}")',
            "",
        ]
        return "\n".join(lines)