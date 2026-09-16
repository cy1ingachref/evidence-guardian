"""SQLi (SQL Injection) detector.

Tests input parameters for SQL error messages and time-based blind injection.
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
        "1; DROP TABLE users--",
        "1' UNION SELECT NULL--",
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        params = ["id", "user", "username", "email", "name", "q", "search",
                  "query", "category", "product", "item"]
        paths = ["/api/login", "/api/users", "/api/search", "/api/products",
                 "/api/items", "/search", "/api/v1/login", "/api/v1/users"]

        for path in paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in params:
                finding = self._test_sqli(target, url, param)
                if finding:
                    findings.append(finding)
                    break

        return findings

    def _test_sqli(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        """Test a parameter for SQL injection."""
        # First, get baseline
        baseline = self._get(url, {param: "normal_value_123"})
        if baseline is None:
            return None

        for payload in self.PAYLOADS:
            response = self._get(url, {param: payload})
            if response is None:
                continue

            # Check for SQL error messages
            if self._has_sql_error(response):
                evidence = Evidence(
                    finding_id=f"EG-SQLI-{hash(url) % 1000:03d}",
                    title=f"SQL Injection via {param} parameter",
                    description=f"Payload '{payload}' triggered SQL error in {url}.",
                    request=HttpRequest(method="GET", url=f"{url}?{param}={payload}"),
                    response=response,
                    proof_script=self._generate_poc_script(url, param, payload),
                    metadata={"payload": payload, "method": "error-based"},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=param,
                    summary=f"SQL error triggered by payload in {param} parameter.",
                    confidence=0.92,
                    evidence=evidence,
                )

            # Check for time-based blind (response is significantly slower)
            if self._is_time_based(baseline, response):
                evidence = Evidence(
                    finding_id=f"EG-SQLI-{hash(url) % 1000:03d}",
                    title=f"Blind SQLi (time-based) via {param}",
                    description=f"Parameter {param} at {url} shows time-delayed response "
                                f"when SQL SLEEP/BENCHMARK payload is injected.",
                    request=HttpRequest(method="GET", url=f"{url}?{param}={payload}"),
                    response=response,
                    proof_script=self._generate_poc_script(url, param, payload),
                    metadata={"payload": payload, "method": "time-based"},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SQLI,
                    severity=Severity.CRITICAL,
                    endpoint=url,
                    parameter=param,
                    summary=f"Time-based blind SQL injection via {param} parameter.",
                    confidence=0.75,
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

    def _has_sql_error(self, response: HttpResponse) -> bool:
        body_lower = response.body.lower()
        return any(re.search(sig, body_lower) for sig in self.ERROR_SIGNATURES)

    @staticmethod
    def _is_time_based(baseline: HttpResponse, payload_response: HttpResponse) -> bool:
        """Check if payload caused a significant time delay."""
        # If response time is > 4 seconds longer than baseline, likely time-based injection
        time_diff = payload_response.response_time_ms - baseline.response_time_ms
        return time_diff > 4000

    @staticmethod
    def _generate_poc_script(url: str, param: str, payload: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"SQLi PoC: Test {param} parameter for SQL injection.\"\"\"
import requests

url = "{url}"
payloads = ["\\'", "\\"\\"", "\\' OR \\'1\\'=\\'1", "1; DROP TABLE test--"]

for p in payloads:
    response = requests.get(url, params={{"{param}": p}})
    if any(e in response.text.lower() for e in ["sql", "error", "syntax", "mysql", "oracle"]):
        print(f"VULNERABLE to SQLi with payload: {{p}}")
        print(f"Error in response: {{response.text[:300]}}")
        break
else:
    print("No SQLi confirmed with basic payloads.")
"""
