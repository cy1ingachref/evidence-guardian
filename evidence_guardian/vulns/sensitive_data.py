"""Sensitive Data Exposure detector.

Finds exposed sensitive files, backup files, debug endpoints, and information leaks.
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


class SensitiveDataExposureModule:
    """Detect exposed sensitive files and information leaks."""

    name = "sensitive_data_exposure"
    description = "Sensitive Data Exposure via accessible files and endpoints"

    SENSITIVE_PATHS = [
        "/.git/HEAD", "/.git/config",
        "/.env", "/.env.backup", "/.env.bak",
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/database.sql", "/dump.sql", "/db.sql",
        "/web.config", "/appsettings.json",
        "/actuator", "/actuator/env",
        "/.aws/credentials",
        "/server-status", "/server-info",
        "/phpinfo.php", "/info.php",
        "/wp-admin", "/wp-login.php",
        "/ftp/", "/ftp/acquisitions.md", "/ftp/coupons_2013.md.bak",
        "/ftp/legal.md", "/ftp/package.json.bak",
        "/api-docs", "/swagger.json", "/openapi.json",
        "/robots.txt", "/sitemap.xml",
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)
        self._baseline_body = None

    def _get_baseline(self, target: ScanTarget) -> str:
        """Get baseline response body (what the server returns for non-existent pages)."""
        if self._baseline_body is None:
            try:
                resp = self.client.get(f"{target.url.rstrip('/')}/this-page-definitely-does-not-exist-12345")
                self._baseline_body = resp.text
            except Exception:
                self._baseline_body = ""
        return self._baseline_body

    def run(self, target: ScanTarget) -> list[Finding]:
        findings = []
        baseline = self._get_baseline(target)

        for path in self.SENSITIVE_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            finding = self._test_sensitive_path(target, url, path, baseline)
            if finding:
                findings.append(finding)

        return findings

    def _test_sensitive_path(self, target: ScanTarget, url: str, path: str, baseline: str) -> Finding | None:
        """Test if a sensitive path is accessible."""
        try:
            resp = self.client.get(url)
            
            if resp.status_code != 200:
                return None
            
            body = resp.text
            
            # Anti-false-positive: if body matches baseline, it's a catch-all
            if self._is_catchall(body, baseline):
                return None
            
            # Git files
            if path.startswith("/.git/"):
                if "ref:" in body or "[core]" in body:
                    return self._create_finding(url, path, "Git repository exposed", body)
            
            # .env files
            if path.startswith("/.env"):
                if any(k in body for k in ["DB_", "APP_", "API_", "KEY", "PASSWORD", "SECRET"]):
                    return self._create_finding(url, path, "Environment file exposed", body)
            
            # Backup files (check content type, not just status)
            if any(ext in path for ext in [".bak", ".backup", ".sql", ".zip", ".tar.gz"]):
                content_type = resp.headers.get("content-type", "")
                if "text" in content_type or "json" in content_type or "octet-stream" in content_type:
                    return self._create_finding(url, path, "Backup file exposed", body)
            
            # FTP directory listing (Juice Shop)
            if path == "/ftp/":
                if "directory" in body.lower() or "<table" in body.lower() or "index of" in body.lower():
                    return self._create_finding(url, path, "FTP directory listing exposed", body)
            
            # AWS credentials
            if ".aws" in path:
                if "AccessKeyId" in body or "SecretAccessKey" in body:
                    return self._create_finding(url, path, "AWS credentials exposed", body)
            
            # Private keys
            if "PRIVATE KEY" in body:
                return self._create_finding(url, path, "Private key exposed", body)
            
            # Juice Shop FTP files
            if path.startswith("/ftp/") and path != "/ftp/":
                if "confidential" in body.lower() or "acquisition" in body.lower() or "coupon" in body.lower():
                    return self._create_finding(url, path, "Confidential document exposed", body)
            
            # Swagger/OpenAPI docs
            if path in ["/api-docs", "/swagger.json", "/openapi.json"]:
                if '"swagger"' in body or '"openapi"' in body:
                    return self._create_finding(url, path, "API documentation exposed", body)
            
            return None
            
        except (httpx.RequestError, httpx.TimeoutException):
            return None

    @staticmethod
    def _is_catchall(body: str, baseline: str) -> bool:
        """Check if response is a catch-all page (same as 404 response)."""
        if not baseline:
            return False
        
        # If bodies are very similar, it's a catch-all
        body_tokens = set(re.findall(r'\w+', body.lower()))
        baseline_tokens = set(re.findall(r'\w+', baseline.lower()))
        
        if not baseline_tokens:
            return False
        
        intersection = body_tokens & baseline_tokens
        union = body_tokens | baseline_tokens
        
        if union:
            similarity = len(intersection) / len(union)
            return similarity > 0.9
        
        return False

    def _create_finding(self, url: str, path: str, title: str, body: str) -> Finding:
        """Create a finding for an exposed sensitive path."""
        redacted_body = self._redact_sensitive(body[:500])
        
        response = HttpResponse(
            status_code=200,
            headers={},
            body=redacted_body,
        )
        
        evidence = Evidence(
            finding_id=_next_finding_id("INFO"),
            title=title,
            description=f"Sensitive path {path} is publicly accessible at {url}.",
            request=HttpRequest(method="GET", url=url),
            response=response,
            proof_script=f"#!/usr/bin/env python3\nimport requests\nresponse = requests.get('{url}')\nprint(response.text[:1000])\n",
            metadata={"path": path},
        )
        
        return Finding(
            id=evidence.finding_id,
            type=VulnType.INFORMATION_DISCLOSURE,
            severity=Severity.MEDIUM,
            endpoint=url,
            parameter="n/a",
            summary=f"{title}: {path}",
            confidence=0.90,
            evidence=evidence,
        )

    @staticmethod
    def _redact_sensitive(text: str) -> str:
        """Redact sensitive data from evidence."""
        text = re.sub(r'(password|secret|key|token)\s*[=:]\s*\S+', r'\1=***REDACTED***', text, flags=re.IGNORECASE)
        text = re.sub(r'AKIA[0-9A-Z]{16}', 'AKIA***REDACTED***', text)
        return text