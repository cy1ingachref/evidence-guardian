"""SSRF (Server-Side Request Forgery) detector.

Finds URL-fetching endpoints and validates whether user-controlled input
reaches server-side requests without proper filtering.

Detection strategy:
1. Send baseline request (parameter with no URL value) to learn normal response
2. Send request with internal URL probe
3. Only flag if the response DIFFERS from baseline AND contains indicators
   of actual internal content (AWS metadata, internal service banners)
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

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
from ..llm import LLMClient


class SSRFModule:
    """Detect SSRF by probing URL parameters with internal addresses."""

    name = "ssrf"
    description = "Server-Side Request Forgery via unvalidated URL parameters"

    def __init__(self, client: httpx.Client | None = None, llm: LLMClient | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)
        self.llm = llm or LLMClient()

    def run(self, target: ScanTarget) -> list[Finding]:
        """Run SSRF detection against the target."""
        findings = []
        endpoints = self._discover_endpoints(target)
        for endpoint in endpoints:
            finding = self._test_endpoint(target, endpoint)
            if finding:
                findings.append(finding)
        return findings

    def _discover_endpoints(self, target: ScanTarget) -> list[dict[str, str]]:
        """Find endpoints that might fetch URLs."""
        candidates = []
        url_params = ["url", "uri", "link", "src", "href", "fetch", "proxy",
                      "callback", "redirect", "next", "target", "endpoint"]

        common_paths = [
            "/api/fetch", "/api/proxy", "/api/webhook", "/api/check",
            "/api/url", "/api/v1/fetch", "/api/v1/proxy",
            "/health", "/status",
            "/rest/products/search", "/rest/user/login",
            "/api/products/search", "/api/users/profile",
            "/api/search", "/api/v1/search",
            "/proxy", "/fetch", "/redirect",
        ]

        for path in common_paths:
            full_url = f"{target.url.rstrip('/')}{path}"
            if target.is_in_scope(full_url):
                for param in url_params:
                    candidates.append({"url": full_url, "param": param})

        return candidates

    def _test_endpoint(self, target: ScanTarget, endpoint: dict[str, str]) -> Finding | None:
        """Test a single endpoint for SSRF vulnerability."""
        url = endpoint["url"]
        param = endpoint["param"]

        # Step 1: Get baseline response
        baseline_response = self._try_fetch(url, param, "baseline-test-12345")
        if baseline_response is None:
            return None

        # Step 2: Test with internal addresses
        internal_probes = [
            ("http://169.254.169.254/latest/meta-data/", "aws_metadata"),
            ("http://127.0.0.1/", "localhost"),
            ("http://[::1]/", "localhost_v6"),
            ("http://internal.local/", "internal_dns"),
        ]

        for internal_url, probe_type in internal_probes:
            response = self._try_fetch(url, param, internal_url)
            if response is None:
                continue

            # Step 3: Compare against baseline
            if self._response_differs_from_baseline(baseline_response, response):
                if self._contains_internal_content(response, probe_type):
                    evidence = Evidence(
                        finding_id=_next_finding_id("SSRF"),
                        title=f"SSRF via {param} parameter",
                        description=f"Endpoint at {url} fetches user-supplied URLs. "
                                    f"Response changed when probing {internal_url} "
                                    f"(baseline: {baseline_response.status_code}, "
                                    f"probe: {response.status_code}). "
                                    f"Response contains {probe_type} indicators.",
                        request=HttpRequest(method="GET", url=f"{url}?{param}={internal_url}"),
                        response=response,
                        proof_script=self._generate_poc_script(url, param, internal_url),
                        metadata={"internal_target": internal_url, "probe_type": probe_type},
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.SSRF,
                        severity=Severity.HIGH,
                        endpoint=url,
                        parameter=param,
                        summary=f"Server fetches user-supplied URLs. "
                                f"Probe to {internal_url} returned different response than baseline.",
                        confidence=0.85,
                        evidence=evidence,
                    )

        return None

    def _try_fetch(self, base_url: str, param: str, target_url: str) -> HttpResponse | None:
        """Attempt to trigger a server-side fetch."""
        try:
            start = time.time()
            resp = self.client.get(base_url, params={param: target_url})
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:3000],
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    @staticmethod
    def _response_differs_from_baseline(baseline: HttpResponse, probe: HttpResponse) -> bool:
        """Check if the probe response is significantly different from baseline."""
        if baseline.status_code != probe.status_code:
            return True

        baseline_len = len(baseline.body)
        probe_len = len(probe.body)
        if baseline_len > 0:
            ratio = abs(probe_len - baseline_len) / baseline_len
            if ratio > 0.2:
                return True

        baseline_tokens = set(re.findall(r'\w+', baseline.body.lower()))
        probe_tokens = set(re.findall(r'\w+', probe.body.lower()))
        
        if not baseline_tokens:
            return len(probe_tokens) > 0

        intersection = baseline_tokens & probe_tokens
        union = baseline_tokens | probe_tokens
        if union:
            similarity = len(intersection) / len(union)
            return similarity < 0.7

        return False

    @staticmethod
    def _contains_internal_content(response: HttpResponse, probe_type: str) -> bool:
        """Check if response contains markers of actual internal service content."""
        body = response.body.lower()

        if probe_type == "aws_metadata":
            aws_indicators = [
                r'\bami-[0-9a-f]{8,17}\b',
                r'\bi-[0-9a-f]{8,17}\b',
                r'"instanceType"\s*:',
                r'"instanceId"\s*:',
                r'"region"\s*:',
                r'"accountId"\s*:',
            ]
            matches = sum(1 for p in aws_indicators if re.search(p, body))
            return matches >= 2

        elif probe_type in ("localhost", "localhost_v6"):
            localhost_indicators = [
                r'\bnginx/\d+\.\d+',
                r'\bapache/\d+\.\d+',
                r'\bserver:\s*(nginx|apache|iis|lighttpd)',
                r'\bx-powered-by:\s*(php|asp\.net|express)',
                r'\bwelcome to\b.*\b(nginx|apache|http)',
                r'\bindex of\b',
            ]
            matches = sum(1 for p in localhost_indicators if re.search(p, body))
            return matches >= 1

        elif probe_type == "internal_dns":
            internal_indicators = [
                r'\binternal\b.*\b(network|service|api)\b',
                r'\bintranet\b',
                r'\bcorp\b',
            ]
            return any(re.search(p, body) for p in internal_indicators)

        return False

    @staticmethod
    def _generate_poc_script(base_url: str, param: str, target: str) -> str:
        return '\n'.join([
            '#!/usr/bin/env python3',
            '"""SSRF PoC: Fetch internal resource via ' + param + ' parameter."""',
            'import requests',
            '',
            'url = "' + base_url + '"',
            'params = {"' + param + '": "' + target + '"}',
            '',
            'response = requests.get(url, params=params, timeout=10)',
            'print(f"Status: {response.status_code}")',
            'print(f"Body (first 500 chars): {response.text[:500]}")',
            '# If this returns content from ' + target + ', SSRF is confirmed.\n',
        ])