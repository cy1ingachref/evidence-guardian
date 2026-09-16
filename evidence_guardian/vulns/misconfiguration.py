"""Security Misconfiguration detector.

Finds debug endpoints, default credentials, insecure headers, and misconfigured services.
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


class SecurityMisconfigurationModule:
    """Detect security misconfigurations."""

    name = "security_misconfiguration"
    description = "Security Misconfiguration: debug endpoints, insecure headers, etc."

    # Debug/development endpoints that shouldn't be in production
    DEBUG_PATHS = [
        "/debug", "/_debug", "/__debug__",
        "/actuator", "/actuator/env", "/actuator/heapdump",
        "/trace", "/metrics",
        "/elmah.axd",
        "/error_log", "/error.log",
    ]

    # Admin interfaces
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administration", "/administration/",
        "/phpmyadmin", "/pma",
        "/wp-admin", "/wp-login",
        "/manager", "/manager/html",
    ]

    # Security headers that should be present
    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []

        # Check debug endpoints
        for path in self.DEBUG_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            finding = self._test_debug_endpoint(target, url, path)
            if finding:
                findings.append(finding)

        # Check admin interfaces
        for path in self.ADMIN_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            finding = self._test_admin_endpoint(target, url, path)
            if finding:
                findings.append(finding)

        # Check security headers (only once per target)
        finding = self._test_security_headers(target)
        if finding:
            findings.append(finding)

        # Check for default error pages (information disclosure)
        finding = self._test_error_handling(target)
        if finding:
            findings.append(finding)

        return findings

    def _test_debug_endpoint(self, target: ScanTarget, url: str, path: str) -> Finding | None:
        """Check if debug endpoint is accessible."""
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                body = resp.text.lower()
                # Check if it's actually a debug page
                if any(ind in body for ind in ["debug", "trace", "stack", "env", "heap", "actuator"]):
                    evidence = Evidence(
                        finding_id=_next_finding_id("CONFIG"),
                        title=f"Debug endpoint exposed: {path}",
                        description=f"Debug endpoint {path} is publicly accessible.",
                        request=HttpRequest(method="GET", url=url),
                        response=HttpResponse(status_code=200, body=resp.text[:500]),
                        proof_script=f"curl {url}\n",
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.SECURITY_MISCONFIGURATION,
                        severity=Severity.HIGH,
                        endpoint=url,
                        parameter="n/a",
                        summary=f"Debug endpoint {path} is publicly accessible.",
                        confidence=0.85,
                        evidence=evidence,
                    )
            return None
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _test_admin_endpoint(self, target: ScanTarget, url: str, path: str) -> Finding | None:
        """Check if admin interface is accessible without authentication."""
        try:
            resp = self.client.get(url)
            if resp.status_code == 200:
                body = resp.text.lower()
                # Check if it's actually an admin page
                if any(ind in body for ind in ["admin", "dashboard", "login", "management", "control panel"]):
                    evidence = Evidence(
                        finding_id=_next_finding_id("CONFIG"),
                        title=f"Admin interface accessible: {path}",
                        description=f"Admin interface {path} is accessible without authentication.",
                        request=HttpRequest(method="GET", url=url),
                        response=HttpResponse(status_code=200, body=resp.text[:500]),
                        proof_script=f"curl {url}\n",
                    )
                    return Finding(
                        id=evidence.finding_id,
                        type=VulnType.SECURITY_MISCONFIGURATION,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter="n/a",
                        summary=f"Admin interface {path} accessible without auth.",
                        confidence=0.80,
                        evidence=evidence,
                    )
            return None
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _test_security_headers(self, target: ScanTarget) -> Finding | None:
        """Check for missing security headers."""
        try:
            resp = self.client.get(target.url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            
            missing = [h for h in self.SECURITY_HEADERS if h not in headers]
            
            if len(missing) >= 3:
                evidence = Evidence(
                    finding_id=_next_finding_id("CONFIG"),
                    title="Missing security headers",
                    description=f"Target is missing {len(missing)} security headers: {', '.join(missing)}.",
                    request=HttpRequest(method="GET", url=target.url),
                    response=HttpResponse(status_code=resp.status_code, headers=dict(resp.headers)),
                    proof_script=f"curl -I {target.url}\n",
                    metadata={"missing_headers": missing},
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SECURITY_MISCONFIGURATION,
                    severity=Severity.LOW,
                    endpoint=target.url,
                    parameter="n/a",
                    summary=f"Missing {len(missing)} security headers.",
                    confidence=0.90,
                    evidence=evidence,
                )
            return None
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _test_error_handling(self, target: ScanTarget) -> Finding | None:
        """Test for verbose error messages that leak information."""
        try:
            # Send a request that should trigger an error
            resp = self.client.get(f"{target.url.rstrip('/')}/%00")
            
            body = resp.text
            # Check for stack traces or verbose errors
            if any(ind in body for ind in ["stack trace", "traceback", "exception", "at line", "syntax error"]):
                evidence = Evidence(
                    finding_id=_next_finding_id("CONFIG"),
                    title="Verbose error messages leak information",
                    description="Server returns verbose error messages that may leak implementation details.",
                    request=HttpRequest(method="GET", url=target.url + "/%00"),
                    response=HttpResponse(status_code=resp.status_code, body=body[:500]),
                    proof_script=f"curl {target.url}/%00\n",
                )
                return Finding(
                    id=evidence.finding_id,
                    type=VulnType.SECURITY_MISCONFIGURATION,
                    severity=Severity.LOW,
                    endpoint=target.url,
                    parameter="n/a",
                    summary="Verbose error messages leak information.",
                    confidence=0.80,
                    evidence=evidence,
                )
            return None
        except (httpx.RequestError, httpx.TimeoutException):
            return None