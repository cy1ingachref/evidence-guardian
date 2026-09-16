"""Authentication & Session Security scanner.

Detects weaknesses in authentication mechanisms, JWT tokens,
session management, password reset flows, and access controls.
"""
from __future__ import annotations

import re
import time
import json
import base64
import hashlib
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


class AuthScanModule:
    """Detect authentication and session management weaknesses."""

    name = "auth_scan"
    description = "Authentication & session security scanning"

    # Common auth endpoints
    AUTH_ENDPOINTS = [
        "/rest/user/login",
        "/api/login",
        "/api/auth/login",
        "/api/v1/auth/login",
        "/api/Users/authenticate",
        "/oauth/token",
        "/auth",
        "/login",
        "/signin",
    ]

    # Password reset endpoints
    RESET_ENDPOINTS = [
        "/rest/user/reset-password",
        "/api/forgot-password",
        "/api/reset-password",
        "/api/v1/auth/forgot-password",
        "/api/v1/auth/reset-password",
        "/forgot-password",
        "/reset-password",
    ]

    # JWT weak secrets for brute-force
    JWT_WEAK_SECRETS = [
        "secret",
        "password",
        "123456",
        "admin",
        "jwt",
        "token",
        "supersecret",
        "changeme",
        "your-256-bit-secret",
        "mysecret",
        "secret123",
        "juice-shop",
        "owasp",
        "",
    ]

    # Default credentials to test
    DEFAULT_CREDS = [
        {"email": "admin@juice-sh.op", "password": "admin123"},
        {"email": "admin@juice-sh.op", "password": "password"},
        {"email": "admin@juice-sh.op", "password": "admin"},
        {"email": "admin@juice-sh.op", "password": "123456"},
        {"email": "admin@example.com", "password": "admin123"},
        {"email": "admin@example.com", "password": "password"},
        {"email": "root", "password": "root"},
        {"email": "admin", "password": "admin"},
        {"email": "administrator", "password": "administrator"},
        {"email": "test@test.com", "password": "test123"},
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        """Run authentication security scans."""
        findings = []

        # Phase 1: Login endpoint analysis
        findings.extend(self._scan_login_endpoints(target))

        # Phase 2: JWT token analysis
        findings.extend(self._analyze_jwt(target))

        # Phase 3: Password reset flow analysis
        findings.extend(self._analyze_password_reset(target))

        # Phase 4: Session management
        findings.extend(self._analyze_session_management(target))

        # Phase 5: Authentication bypass
        findings.extend(self._detect_auth_bypass(target))

        return findings

    def _scan_login_endpoints(self, target: ScanTarget) -> list[Finding]:
        """Scan login endpoints for security issues."""
        findings = []

        for path in self.AUTH_ENDPOINTS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            # Check if endpoint exists
            baseline = self._post_json(url, {"email": "test@test.com", "password": "wrong"})
            if baseline is None or baseline.status_code == 404:
                continue

            # Test 1: Check for rate limiting
            if not self._has_rate_limiting(url):
                evidence = Evidence(
                    finding_id=_next_finding_id("AUTH"),
                    title="Login endpoint lacks rate limiting",
                    description=f"Endpoint {url} does not appear to have rate limiting. Vulnerable to brute force attacks.",
                    request=HttpRequest(method="POST", url=url, body="Multiple rapid login attempts"),
                    response=HttpResponse(status_code=200, body="No rate limit detected after 10 attempts"),
                )
                findings.append(Finding(
                    id=evidence.finding_id,
                    type=VulnType.BROKEN_AUTHENTICATION,
                    severity=Severity.HIGH,
                    endpoint=url,
                    parameter="credentials",
                    summary="Login endpoint lacks rate limiting.",
                    confidence=0.75,
                    evidence=evidence,
                ))

            # Test 2: Check error messages for user enumeration
            resp_valid_user = self._post_json(url, {"email": "admin@juice-sh.op", "password": "wrong"})
            resp_invalid_user = self._post_json(url, {"email": "nonexistent@test.com", "password": "wrong"})

            if resp_valid_user and resp_invalid_user:
                if resp_valid_user.body != resp_invalid_user.body:
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title="User enumeration via login endpoint",
                        description=f"Endpoint {url} returns different responses for valid vs invalid users.",
                        request=HttpRequest(method="POST", url=url, body="Valid vs invalid user test"),
                        response=HttpResponse(status_code=200, body="Different error messages for valid/invalid users"),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter="email",
                        summary="User enumeration via login endpoint.",
                        confidence=0.80,
                        evidence=evidence,
                    ))

            # Test 3: Default credentials
            for creds in self.DEFAULT_CREDS[:5]:
                resp = self._post_json(url, creds)
                if resp and resp.status_code == 200:
                    body = resp.body
                    if any(ind in body.lower() for ind in ["token", "success", "authenticated", "logged"]):
                        evidence = Evidence(
                            finding_id=_next_finding_id("AUTH"),
                            title="Default credentials accepted",
                            description=f"Default credentials accepted: {creds['email']} / {creds['password']}",
                            request=HttpRequest(method="POST", url=url, body=str(creds)),
                            response=HttpResponse(status_code=200, body=body[:300]),
                            metadata={"credentials": creds},
                        )
                        findings.append(Finding(
                            id=evidence.finding_id,
                            type=VulnType.BROKEN_AUTHENTICATION,
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            parameter="credentials",
                            summary=f"Default credentials: {creds['email']} / {creds['password']}",
                            confidence=0.95,
                            evidence=evidence,
                        ))
                        break

        return findings

    def _analyze_jwt(self, target: ScanTarget) -> list[Finding]:
        """Analyze JWT token security."""
        findings = []

        # First, try to obtain a JWT token
        token = None
        for path in ["/rest/user/login", "/api/login", "/api/Users/authenticate"]:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for creds in self.DEFAULT_CREDS[:3]:
                resp = self._post_json(url, creds)
                if resp and resp.status_code == 200:
                    try:
                        data = json.loads(resp.text)
                        # Try common JWT locations in response
                        token = (
                            data.get("authentication", {}).get("token")
                            or data.get("token")
                            or data.get("access_token")
                            or data.get("jwt")
                        )
                        if token:
                            break
                    except (json.JSONDecodeError, KeyError):
                        continue
            if token:
                break

        if not token:
            return findings

        # Analyze JWT structure
        parts = token.split(".")
        if len(parts) != 3:
            return findings

        # Decode header and payload
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return findings

        # Check 1: Algorithm "none" attack
        if header.get("alg", "").lower() == "none":
            evidence = Evidence(
                finding_id=_next_finding_id("AUTH"),
                title="JWT algorithm 'none' accepted",
                description="Server accepts JWT tokens with algorithm 'none'. Forged tokens possible.",
                request=HttpRequest(method="GET", url=target.url, headers={"Authorization": f"Bearer {token}"}),
                response=HttpResponse(status_code=200, body="Algorithm: none in JWT header"),
            )
            findings.append(Finding(
                id=evidence.finding_id,
                type=VulnType.BROKEN_AUTHENTICATION,
                severity=Severity.CRITICAL,
                endpoint=target.url,
                parameter="JWT",
                summary="JWT algorithm 'none' accepted.",
                confidence=0.95,
                evidence=evidence,
            ))

        # Check 2: HS256 with weak secret
        if header.get("alg") == "HS256":
            for secret in self.JWT_WEAK_SECRTS:
                if self._verify_jwt_secret(token, secret):
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title="JWT signed with weak secret",
                        description=f"JWT can be forged with weak secret: '{secret}'",
                        request=HttpRequest(method="GET", url=target.url, headers={"Authorization": f"Bearer {token}"}),
                        response=HttpResponse(status_code=200, body=f"Weak secret found: {secret}"),
                        metadata={"secret": secret},
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.CRITICAL,
                        endpoint=target.url,
                        parameter="JWT",
                        summary=f"JWT weak secret: '{secret}'",
                        confidence=0.95,
                        evidence=evidence,
                    ))
                    break

        # Check 3: Missing expiration
        if "exp" not in payload:
            evidence = Evidence(
                finding_id=_next_finding_id("AUTH"),
                title="JWT token lacks expiration",
                description="JWT token does not have an 'exp' claim. Token never expires.",
                request=HttpRequest(method="GET", url=target.url, headers={"Authorization": f"Bearer {token}"}),
                response=HttpResponse(status_code=200, body="No expiration claim in JWT"),
            )
            findings.append(Finding(
                id=evidence.finding_id,
                type=VulnType.BROKEN_AUTHENTICATION,
                severity=Severity.MEDIUM,
                endpoint=target.url,
                parameter="JWT",
                summary="JWT token lacks expiration.",
                confidence=0.90,
                evidence=evidence,
            ))

        # Check 4: Sensitive data in JWT payload
        sensitive_fields = ["password", "ssn", "credit_card", "secret", "role", "isAdmin"]
        leaked = [f for f in sensitive_fields if f in payload]
        if leaked:
            evidence = Evidence(
                finding_id=_next_finding_id("AUTH"),
                title="Sensitive data in JWT payload",
                description=f"JWT payload contains sensitive fields: {', '.join(leaked)}",
                request=HttpRequest(method="GET", url=target.url, headers={"Authorization": f"Bearer {token}"}),
                response=HttpResponse(status_code=200, body=f"Sensitive fields: {', '.join(leaked)}"),
                metadata={"sensitive_fields": leaked},
            )
            findings.append(Finding(
                id=evidence.finding_id,
                type=VulnType.BROKEN_AUTHENTICATION,
                severity=Severity.MEDIUM,
                endpoint=target.url,
                parameter="JWT",
                summary=f"Sensitive data in JWT: {', '.join(leaked)}",
                confidence=0.90,
                evidence=evidence,
            ))

        return findings

    def _verify_jwt_secret(self, token: str, secret: str) -> bool:
        """Verify if a JWT token was signed with the given secret."""
        import hmac
        parts = token.split(".")
        signature = parts[2]
        message = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), message, hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        return signature == expected_sig

    def _analyze_password_reset(self, target: ScanTarget) -> list[Finding]:
        """Analyze password reset flow security."""
        findings = []

        for path in self.RESET_ENDPOINTS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            # Check if endpoint exists
            baseline = self._post_json(url, {"email": "test@test.com"})
            if baseline is None or baseline.status_code == 404:
                continue

            # Test for user enumeration
            resp_valid = self._post_json(url, {"email": "admin@juice-sh.op"})
            resp_invalid = self._post_json(url, {"email": "nonexistent@test.com"})

            if resp_valid and resp_invalid:
                if resp_valid.body != resp_invalid.body:
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title="Password reset user enumeration",
                        description=f"Endpoint {url} reveals if email exists during password reset.",
                        request=HttpRequest(method="POST", url=url, body="Email enumeration test"),
                        response=HttpResponse(status_code=200, body="Different responses for valid/invalid emails"),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.MEDIUM,
                        endpoint=url,
                        parameter="email",
                        summary="Password reset user enumeration.",
                        confidence=0.80,
                        evidence=evidence,
                    ))

            break  # Only test first available endpoint

        return findings

    def _analyze_session_management(self, target: ScanTarget) -> list[Finding]:
        """Analyze session cookie security."""
        findings = []

        try:
            resp = self.client.get(target.url)
            cookies = resp.cookies

            for cookie in cookies:
                # Check for missing HttpOnly flag
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title=f"Session cookie missing HttpOnly: {cookie.name}",
                        description=f"Cookie '{cookie.name}' does not have HttpOnly flag. Accessible via JavaScript.",
                        request=HttpRequest(method="GET", url=target.url),
                        response=HttpResponse(status_code=200, body=f"Cookie: {cookie.name}"),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.MEDIUM,
                        endpoint=target.url,
                        parameter=cookie.name,
                        summary=f"Cookie missing HttpOnly: {cookie.name}",
                        confidence=0.85,
                        evidence=evidence,
                    ))

                # Check for missing Secure flag
                if not cookie.has_nonstandard_attr("Secure"):
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title=f"Session cookie missing Secure flag: {cookie.name}",
                        description=f"Cookie '{cookie.name}' does not have Secure flag. Sent over HTTP.",
                        request=HttpRequest(method="GET", url=target.url),
                        response=HttpResponse(status_code=200, body=f"Cookie: {cookie.name}"),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.LOW,
                        endpoint=target.url,
                        parameter=cookie.name,
                        summary=f"Cookie missing Secure flag: {cookie.name}",
                        confidence=0.85,
                        evidence=evidence,
                    ))

                # Check for missing SameSite attribute
                if not cookie.has_nonstandard_attr("SameSite"):
                    evidence = Evidence(
                        finding_id=_next_finding_id("AUTH"),
                        title=f"Session cookie missing SameSite: {cookie.name}",
                        description=f"Cookie '{cookie.name}' does not have SameSite attribute.",
                        request=HttpRequest(method="GET", url=target.url),
                        response=HttpResponse(status_code=200, body=f"Cookie: {cookie.name}"),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.BROKEN_AUTHENTICATION,
                        severity=Severity.LOW,
                        endpoint=target.url,
                        parameter=cookie.name,
                        summary=f"Cookie missing SameSite: {cookie.name}",
                        confidence=0.85,
                        evidence=evidence,
                    ))

        except (httpx.RequestError, httpx.TimeoutException):
            pass

        return findings

    def _detect_auth_bypass(self, target: ScanTarget) -> list[Finding]:
        """Detect authentication bypass vulnerabilities."""
        findings = []

        # Common protected endpoints
        protected_paths = [
            "/rest/user/whoami",
            "/api/Users/me",
            "/rest/admin",
            "/administration",
            "/api/admin",
            "/rest/basket",
            "/api/Orders",
        ]

        # SQLi bypass payloads
        sqli_bypass_payloads = [
            {"email": "' OR '1'='1", "password": "' OR '1'='1"},
            {"email": "admin'--", "password": "x"},
            {"email": "' OR 1=1--", "password": "x"},
        ]

        for path in self.AUTH_ENDPOINTS[:3]:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            for payload in sqli_bypass_payloads:
                resp = self._post_json(url, payload)
                if resp and resp.status_code == 200:
                    body = resp.text
                    if any(ind in body.lower() for ind in ["token", "success", "authenticated"]):
                        evidence = Evidence(
                            finding_id=_next_finding_id("AUTH"),
                            title="Authentication bypass via SQLi",
                            description=f"SQLi bypass at {url} with payload: {payload}",
                            request=HttpRequest(method="POST", url=url, body=str(payload)),
                            response=HttpResponse(status_code=200, body=body[:300]),
                            metadata={"payload": payload},
                        )
                        findings.append(Finding(
                            id=evidence.finding_id,
                            type=VulnType.BROKEN_AUTHENTICATION,
                            severity=Severity.CRITICAL,
                            endpoint=url,
                            parameter="credentials",
                            summary="Authentication bypass via SQLi.",
                            confidence=0.85,
                            evidence=evidence,
                        ))
                        return findings

            break

        return findings

    def _has_rate_limiting(self, url: str) -> bool:
        """Check if endpoint has rate limiting."""
        try:
            # Send rapid requests
            for _ in range(10):
                resp = self.client.post(url, json={"email": "test@test.com", "password": "wrong"})
                if resp.status_code == 429:  # Too Many Requests
                    return True
            return False
        except (httpx.RequestError, httpx.TimeoutException):
            return True  # Assume rate limited on error

    def _post_json(self, url: str, json_data: dict) -> HttpResponse | None:
        try:
            resp = self.client.post(url, json=json_data)
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:3000],
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    def _post_form(self, url: str, data: dict[str, str]) -> HttpResponse | None:
        try:
            resp = self.client.post(url, data=data)
            return HttpResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text[:3000],
            )
        except (httpx.RequestError, httpx.TimeoutException):
            return None