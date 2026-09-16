"""API Endpoint Discovery module.

Discovers API endpoints by parsing OpenAPI/Swagger specs, common patterns,
and crawling links in responses.
"""
from __future__ import annotations

import re
import time
import json
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


class EndpointDiscoveryModule:
    """Discover API endpoints through specs and crawling."""

    name = "endpoint_discovery"
    description = "API endpoint discovery via OpenAPI/Swagger and crawling"

    # Common API documentation paths
    API_DOC_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/api-docs",
        "/api-docs.json",
        "/openapi.json",
        "/openapi.yaml",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/doc.html",
        "/api-doc",
        "/api/docs",
        "/docs",
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/graphiql",
        "/playground",
    ]

    # Common API patterns to discover
    API_PATTERNS = [
        r'["\'](/api/[^"\']+)["\']',
        r'["\'](/v\d+/[^"\']+)["\']',
        r'["\'](/rest/[^"\']+)["\']',
        r'["\'](/graphql[^"\']*)["\']',
        r'href=["\']([^"\']*swagger[^"\']*)["\']',
        r'href=["\']([^"\']*api-doc[^"\']*)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'path:\s*["\']([^"\']+)["\']',
        r'endpoint:\s*["\']([^"\']+)["\']',
        r'/api/[a-zA-Z0-9_-]+',
        r'/v\d+/[a-zA-Z0-9_-]+',
        r'/rest/[a-zA-Z0-9_-]+',
    ]

    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(timeout=15.0, follow_redirects=True)

    def run(self, target: ScanTarget) -> list[Finding]:
        """Run endpoint discovery."""
        findings = []

        # Phase 1: Find and parse API documentation
        endpoints = set()
        for path in self.API_DOC_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            discovered = self._parse_api_doc(url, path)
            endpoints.update(discovered)

        # Phase 2: Crawl responses for API patterns
        crawled = self._crawl_for_endpoints(target)
        endpoints.update(crawled)

        # Report discovered endpoints
        if endpoints:
            endpoint_list = sorted(endpoints)
            evidence = Evidence(
                finding_id=_next_finding_id("DISCOVERY"),
                title=f"Discovered {len(endpoints)} API endpoints",
                description=f"Found {len(endpoints)} potential API endpoints through spec parsing and crawling.",
                request=HttpRequest(method="GET", url=target.url),
                response=HttpResponse(status_code=200, body="\n".join(endpoint_list[:50])),
                metadata={"endpoints": endpoint_list},
            )
            findings.append(Finding(
                id=evidence.finding_id,
                type=VulnType.INFORMATION_DISCLOSURE,
                severity=Severity.LOW,
                endpoint=target.url,
                parameter="n/a",
                summary=f"Discovered {len(endpoints)} API endpoints.",
                confidence=0.90,
                evidence=evidence,
            ))

        return findings

    def _parse_api_doc(self, url: str, path: str) -> set[str]:
        """Parse OpenAPI/Swagger documentation."""
        endpoints = set()

        try:
            resp = self.client.get(url)
            if resp.status_code != 200:
                return endpoints

            body = resp.text

            # Try to parse as JSON/YAML
            try:
                spec = json.loads(body)
            except json.JSONDecodeError:
                # Try YAML-like parsing
                spec = None

            if spec:
                # OpenAPI 3.x
                if "openapi" in spec and "paths" in spec:
                    for path_spec in spec.get("paths", {}):
                        methods = spec["paths"][path_spec]
                        if isinstance(methods, dict):
                            for method in methods:
                                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                    endpoints.add(f"{method.upper()} {path_spec}")

                # Swagger 2.0
                elif "swagger" in spec and "paths" in spec:
                    for path_spec in spec.get("paths", {}):
                        methods = spec["paths"][path_spec]
                        if isinstance(methods, dict):
                            for method in methods:
                                if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                                    endpoints.add(f"{method.upper()} {path_spec}")

                # Extract server/base URL
                servers = spec.get("servers", [])
                if servers and isinstance(servers[0], dict):
                    base_url = servers[0].get("url", "")
                    if base_url:
                        endpoints.add(f"BASE_URL: {base_url}")

            # Also try regex patterns for embedded URLs
            for pattern in self.API_PATTERNS:
                matches = re.findall(pattern, body)
                for match in matches:
                    if isinstance(match, str) and len(match) > 1:
                        endpoints.add(match)

        except (httpx.RequestError, httpx.TimeoutException, Exception):
            pass

        return endpoints

    def _crawl_for_endpoints(self, target: ScanTarget) -> set[str]:
        """Crawl common pages for API endpoint references."""
        endpoints = set()

        crawl_paths = [
            "/",
            "/index.html",
            "/app",
            "/login",
            "/api",
        ]

        for path in crawl_paths:
            url = f"{target.url.rstrip('/')}{path}"
            if not target.is_in_scope(url):
                continue

            try:
                resp = self.client.get(url)
                if resp.status_code != 200:
                    continue

                body = resp.text

                # Search for API patterns
                for pattern in self.API_PATTERNS:
                    matches = re.findall(pattern, body)
                    for match in matches:
                        if isinstance(match, str) and len(match) > 2:
                            endpoints.add(match)

                # Look for fetch/XHR calls
                fetch_patterns = [
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                    r'\.ajax\(\{[^}]*url:\s*["\']([^"\']+)["\']',
                    r'XMLHttpRequest\(\)[^;]*open\(["\'](?:[A-Z]+)["\'],\s*["\']([^"\']+)["\']',
                ]
                for pattern in fetch_patterns:
                    matches = re.findall(pattern, body)
                    for match in matches:
                        if isinstance(match, str) and len(match) > 2:
                            endpoints.add(match)

            except (httpx.RequestError, httpx.TimeoutException):
                continue

        return endpoints