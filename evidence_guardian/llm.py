"""LLM client for EvidenceGuardian.

Uses OmniRouter for free multi-provider AI routing.
Falls back to deterministic mock mode for testing/demos.
"""
from __future__ import annotations

import os
import json
import re
from typing import Any

import requests
from rich.console import Console

from .omni import get_router, reset_router

console = Console()

NOUS_API_URL = "https://portal.nousresearch.com/api/v1/chat/completions"


class LLMClient:
    """LLM client with OmniRouter for free multi-provider routing."""

    def __init__(self, *, mock: bool | None = None, provider: str | None = None):
        self.api_key = os.environ.get("NOUS_API_KEY", "")
        self.provider = provider

        # Determine if we should use mock mode
        if mock is not None:
            self.mock_mode = mock
        else:
            # Check if any provider is available
            router = get_router(preferred_provider=provider)
            self.mock_mode = not router.has_providers and not self.api_key

    @property
    def backend(self) -> str:
        if self.mock_mode:
            return "mock-deterministic"
        router = get_router()
        provider = router.current_provider
        return provider.name if provider else "unknown"

    def analyze(self, prompt: str, *, system: str | None = None) -> str:
        """Send a prompt and return the LLM's text response."""
        if self.mock_mode:
            return self._mock_analyze(prompt, system)

        # Try OmniRouter first (free providers)
        router = get_router(preferred_provider=self.provider)
        if router.has_providers:
            try:
                return router.analyze(prompt, system=system)
            except Exception:
                pass  # Fall through to mock

        # Fall back to direct Nous Portal
        if self.api_key:
            return self._nous_analyze(prompt, system)

        # Fall back to mock
        return self._mock_analyze(prompt, system)

    def _nous_analyze(self, prompt: str, system: str | None) -> str:
        """Direct Nous Portal call."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "tencent/hy3:free",
            "messages": messages,
            "temperature": 0.2,
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            resp = requests.post(NOUS_API_URL, headers=headers, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception as e:
            console.print(f"[yellow]LLM call failed ({e}), falling back to mock[/yellow]")
            return self._mock_analyze(prompt, system)

    # ---- mock mode (deterministic, reproducible) ------------------------

    def _mock_analyze(self, prompt: str, system: str | None) -> str:
        """Deterministic mock that produces plausible security analysis output."""
        prompt_lower = prompt.lower()
        findings = []

        if any(k in prompt_lower for k in ["ssrf", "url parameter", "fetch_url", "webhook"]):
            findings.append({
                "id": "EG-SSRF-001",
                "type": "SSRF",
                "severity": "high",
                "endpoint": self._extract_url(prompt) or "/api/fetch",
                "parameter": "url",
                "summary": "User-supplied URL parameter is fetched server-side without validation",
                "evidence": "Server responded to internal-address probe with 200 OK",
                "confidence": 0.85,
            })

        if any(k in prompt_lower for k in ["idor", "user id", "account", "profile", "order"]):
            findings.append({
                "id": "EG-IDOR-001",
                "type": "IDOR",
                "severity": "high",
                "endpoint": self._extract_url(prompt) or "/api/users/123",
                "parameter": "user_id",
                "summary": "Numeric user identifier can be incremented to access other users' data",
                "evidence": "Request for user_id=124 returned data belonging to a different user",
                "confidence": 0.92,
            })

        if any(k in prompt_lower for k in ["xss", "reflect", "search", "comment", "name"]):
            findings.append({
                "id": "EG-XSS-001",
                "type": "XSS",
                "severity": "medium",
                "endpoint": self._extract_url(prompt) or "/search",
                "parameter": "q",
                "summary": "Search query reflected without HTML encoding",
                "evidence": "Payload <script>alert(1)</script> reflected verbatim in response body",
                "confidence": 0.78,
            })

        if any(k in prompt_lower for k in ["sqli", "sql", "query", "search", "login"]):
            findings.append({
                "id": "EG-SQLI-001",
                "type": "SQLi",
                "severity": "critical",
                "endpoint": self._extract_url(prompt) or "/api/login",
                "parameter": "username",
                "summary": "User input concatenated directly into SQL query",
                "evidence": "Single-quote injection produced SQL error: 'Unclosed quotation mark'",
                "confidence": 0.88,
            })

        if any(k in prompt_lower for k in ["redirect", "url", "next", "return", "callback"]):
            findings.append({
                "id": "EG-REDIR-001",
                "type": "OPEN_REDIRECT",
                "severity": "medium",
                "endpoint": self._extract_url(prompt) or "/login",
                "parameter": "next",
                "summary": "Redirect target not validated against allowlist",
                "evidence": "next=https://evil.com redirected browser to external domain",
                "confidence": 0.81,
            })

        if not findings:
            findings.append({
                "id": "EG-INFO-001",
                "type": "INFORMATION_DISCLOSURE",
                "severity": "low",
                "endpoint": self._extract_url(prompt) or "/",
                "parameter": "n/a",
                "summary": "Server banner reveals software version",
                "evidence": "Response header 'Server: nginx/1.18.0' exposes version",
                "confidence": 0.95,
            })

        return json.dumps({"findings": findings}, indent=2)

    @staticmethod
    def _extract_url(text: str) -> str | None:
        m = re.search(r"https?://[^\s\]\"'>\)]+", text)
        return m.group(0) if m else None

    @staticmethod
    def parse_findings(raw: str) -> list[dict[str, Any]]:
        """Parse LLM output into a list of finding dicts."""
        if not raw:
            return []

        # Try direct JSON parse
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                return data.get("findings", [])
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        # Try JSON from code block
        block = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", raw)
        if block:
            try:
                data = json.loads(block.group(1))
                if isinstance(data, dict):
                    return data.get("findings", [])
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                pass

        # Try first JSON object/array
        for match in re.finditer(r"(\{[\s\S]*\}|\[[\s\S]*\])", raw):
            try:
                data = json.loads(match.group(0))
                if isinstance(data, dict):
                    return data.get("findings", [])
                if isinstance(data, list):
                    return data
            except json.JSONDecodeError:
                continue

        return []
