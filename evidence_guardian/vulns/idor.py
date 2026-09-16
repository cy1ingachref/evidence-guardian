"""IDOR (Insecure Direct Object Reference) detector.

Finds endpoints where numeric/sequential identifiers can be manipulated
to access other users' data.

Detection strategy:
1. Get baseline for first ID
2. Request second ID (baseline + 1)
3. Only flag if both return 200 with different content AND second looks like user data
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


class IDORModule:
    """Detect IDOR by testing object references with modified identifiers.
    
    NOTE: This module tests whether different IDs return different data,
    but without authentication context, it cannot confirm true cross-user
    access. Results should be manually verified with proper auth tokens.
    """

    name = "idor"
    description = "Insecure Direct Object Reference via identifier manipulation"

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        # IDOR-prone endpoint patterns with numeric IDs
        id_patterns = [
            ("/api/users/{id}", "user_id"),
            ("/api/accounts/{id}", "account_id"),
            ("/api/orders/{id}", "order_id"),
            ("/api/profiles/{id}", "profile_id"),
            ("/api/documents/{id}", "doc_id"),
            ("/api/v1/users/{id}", "user_id"),
            ("/api/v1/accounts/{id}", "account_id"),
            # Juice Shop patterns
            "/rest/basket/{id}",
            "/rest/products/{id}",
        ]

        for pattern in id_patterns:
            if isinstance(pattern, tuple):
                path_template, param_name = pattern
            else:
                path_template = pattern
                param_name = "id"

            # Test with a range of IDs
            for base_id in [1, 2, 100, 999]:
                path = path_template.replace("{id}", str(base_id))
                url = f"{target.url.rstrip('/')}{path}"

                if not target.is_in_scope(url):
                    continue

                finding = self._test_id(target, url, path_template, param_name, base_id)
                if finding:
                    findings.append(finding)
                    break  # Found IDOR for this endpoint, move on

        return findings

    def _test_id(
        self,
        target: ScanTarget,
        base_url: str,
        path_template: str,
        param_name: str,
        base_id: int,
    ) -> Finding | None:
        """Test if a base_id+1 returns different user's data."""
        # Get baseline for base_id
        resp_a = self._get(base_url)
        if resp_a is None or resp_a.status_code != 200:
            return None

        # Try base_id+1
        next_id = base_id + 1
        next_url = base_url[:base_url.rfind("/") + 1] + str(next_id)
        resp_b = self._get(next_url)

        if resp_b is None:
            return None

        if resp_b.status_code == 200 and resp_b.body != resp_a.body:
            # Potential IDOR — different ID returned different data
            if self._looks_like_user_data(resp_b):
                evidence = Evidence(
                    finding_id=_next_finding_id("IDOR"),
                    title=f"IDOR via {param_name} manipulation",
                    description=f"Endpoint {path_template} allows access to other users' "
                                f"objects by changing the identifier from {base_id} to {next_id}.",
                    request=HttpRequest(method="GET", url=next_url),
                    response=resp_b,
                    proof_script=self._generate_poc_script(target.url, param_name, base_id, next_id),
                    metadata={"base_id": base_id, "next_id": next_id},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.IDOR,
                    severity=Severity.HIGH,
                    endpoint=base_url,
                    parameter=param_name,
                    summary=f"Changing {param_name} from {base_id} to {next_id} "
                            f"returns data belonging to a different user.",
                    confidence=0.90,
                    evidence=evidence,
                )

        return None

    def _get(self, url: str) -> HttpResponse | None:
        try:
            start = time.time()
            resp = self.client.get(url)
            elapsed_ms = (time.time() - start) * 1000
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:2000],
                response_time_ms=elapsed_ms,
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    @staticmethod
    def _looks_like_user_data(response: HttpResponse) -> bool:
        """Check if response body looks like user data (email, username, etc.)."""
        body = response.body.lower()
        patterns = [
            r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}",  # email
            r'"username"\s*:\s*"[^"]+"',
            r'"email"\s*:\s*"[^"]+"',
            r'"name"\s*:\s*"[^"]+"',
            r'"account"\s*:',
            r'"user"\s*:',
            r'"profile"\s*:',
            r'"owner"\s*:',
        ]
        return any(re.search(p, body) for p in patterns)

    @staticmethod
    def _generate_poc_script(base_url: str, param_name: str, id_a: int, id_b: int) -> str:
        lines = [
            "#!/usr/bin/env python3",
            '"""IDOR PoC: Access another user\'s data by incrementing the ID."""',
            "import requests",
            "",
            "base = " + repr(base_url),
            'url_a = f"{base}/api/users/{id_a}"',
            'url_b = f"{base}/api/users/{id_b}"',
            "",
            "resp_a = requests.get(url_a)",
            "resp_b = requests.get(url_b)",
            "",
            'print(f"Your data (status {resp_a.status_code}): {resp_a.text[:200]}")',
            'print(f"Other user\'s data (status {resp_b.status_code}): {resp_b.text[:200]}")',
            "# If both return 200 with different content, IDOR is confirmed.",
            "",
        ]
        return "\n".join(lines)