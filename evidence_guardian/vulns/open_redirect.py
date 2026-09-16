"""Open Redirect detector.

Finds redirect parameters that don't validate the target against an allowlist.
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
)


class OpenRedirectModule:
    """Detect open redirect by testing redirect parameters with external URLs."""

    name = "open_redirect"
    description = "Open Redirect via unvalidated redirect parameters"

    REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnTo",
                       "redirect_uri", "callback", "goto", "rurl", "target"]

    TEST_TARGET = "https://evil.example.com/redirected"

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(
            timeout=15.0, follow_redirects=False  # Don't follow — we want to see the Location header
        )

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        paths = ["/login", "/logout", "/auth", "/oauth/authorize",
                 "/api/login", "/api/logout", "/redirect", "/api/v1/auth"]

        for path in paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for param in self.REDIRECT_PARAMS:
                finding = self._test_redirect(target, url, param)
                if finding:
                    findings.append(finding)
                    break

        return findings

    def _test_redirect(self, target: ScanTarget, url: str, param: str) -> Finding | None:
        """Test if a redirect parameter accepts external URLs."""
        try:
            start = time.time()
            resp = self.client.get(url, params={param: self.TEST_TARGET})
            elapsed_ms = (time.time() - start) * 1000

            # Check for redirect to external domain
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                parsed = urlparse(location)
                target_host = urlparse(target.url).hostname

                # If redirect goes to external domain, it's vulnerable
                if parsed.hostname and parsed.hostname != target_host:
                    response = HttpResponse(
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=f"Location: {location}",
                        response_time_ms=elapsed_ms,
                    )
                    evidence = Evidence(
                        finding_id=f"EG-REDIR-{hash(url) % 1000:03d}",
                        title=f"Open Redirect via {param} parameter",
                        description=f"Parameter {param} at {url} redirects to user-supplied "
                                    f"external URL without validation.",
                        request=HttpRequest(method="GET", url=f"{url}?{param}={self.TEST_TARGET}"),
                        response=response,
                        proof_script=self._generate_poc_script(url, param, self.TEST_TARGET),
                        metadata={"redirect_location": location},
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.OPEN_REDIRECT,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter=param,
                        summary=f"Open redirect: {param} redirects to external domain.",
                        confidence=0.87,
                        evidence=evidence,
                    )
        except (httpx.RequestError, httpx.TimeoutException):
            pass

        return None

    @staticmethod
    def _generate_poc_script(url: str, param: str, target_url: str) -> str:
        return f"""#!/usr/bin/env python3
\"\"\"Open Redirect PoC: Test {param} for external redirect.\"\"\"
import requests

url = "{url}"
redirect_url = "{target_url}"

response = requests.get(url, params={{"{param}": redirect_url}}, allow_redirects=False)
location = response.headers.get("Location", "")

if redirect_url in location:
    print(f"VULNERABLE: Server redirects to {{location}}")
else:
    print(f"NOT CONFIRMED: Location header was {{location}}")
"""
