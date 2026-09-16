"""Custom Module API for EvidenceGuardian.

Allows users to create pluggable vulnerability detection modules
without modifying the core framework.

Usage:
    from evidence_guardian.custom_module import CustomModule, register_module

    class MyCustomScanner(CustomModule):
        name = "my_scanner"
        description = "Scans for custom vulnerability X"

        def run(self, target: ScanTarget) -> list[Finding]:
            findings = []
            # Your scanning logic here
            return findings

    # Register the module
    register_module(MyCustomScanner)
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path
from typing import Any, Type

# Forward references - these will be imported at runtime
Finding = None
ScanTarget = None
Evidence = None
HttpRequest = None
HttpResponse = None
VulnType = None
Severity = None
_next_finding_id = None


def _lazy_import():
    """Lazy import to avoid circular imports."""
    global Finding, ScanTarget, Evidence, HttpRequest, HttpResponse, VulnType, Severity, _next_finding_id
    if Finding is None:
        from .core import Finding, ScanTarget, Evidence, HttpRequest, HttpResponse, VulnType, Severity, _next_finding_id


# Registry of custom modules
_module_registry: dict[str, Type["CustomModule"]] = {}


class CustomModule:
    """Base class for custom vulnerability detection modules.

    Subclass this to create your own scanner module.
    """

    name: str = "custom"
    description: str = "Custom vulnerability scanner"
    author: str = "anonymous"
    version: str = "1.0.0"

    def __init__(self, client: Any = None, **kwargs: Any):
        """Initialize the module with an optional HTTP client."""
        self.client = client
        self.config = kwargs

    def run(self, target: ScanTarget) -> list[Finding]:
        """Run the module against the target.

        Must be implemented by subclasses.

        Args:
            target: The scan target with URL and scope

        Returns:
            List of Finding objects
        """
        raise NotImplementedError("Subclasses must implement run()")

    def get_baseline(self, target: ScanTarget, path: str = "/") -> tuple[str, int]:
        """Get baseline response for catch-all detection."""
        import httpx

        _lazy_import()

        try:
            if self.client:
                resp = self.client.get(f"{target.url.rstrip('/')}{path}")
            else:
                resp = httpx.get(f"{target.url.rstrip('/')}{path}")
            return resp.text, resp.status_code
        except Exception:
            return "", 404

    def is_catchall(self, body: str, baseline: str, threshold: float = 0.9) -> bool:
        """Check if response is a catch-all page."""
        import re

        if not baseline:
            return False

        body_tokens = set(re.findall(r'\w+', body.lower()))
        baseline_tokens = set(re.findall(r'\w+', baseline.lower()))

        if not baseline_tokens:
            return False

        intersection = body_tokens & baseline_tokens
        union = body_tokens | baseline_tokens

        if union:
            return len(intersection) / len(union) > threshold

        return False


def register_module(module_class: Type[CustomModule]) -> None:
    """Register a custom module class."""
    _module_registry[module_class.name] = module_class


def get_registered_modules() -> dict[str, Type[CustomModule]]:
    """Get all registered custom modules."""
    return dict(_module_registry)


def load_module_from_file(path: str) -> Type[CustomModule] | None:
    """Load a custom module from a Python file.

    Args:
        path: Path to .py file containing a CustomModule subclass

    Returns:
        The loaded module class
    """
    try:
        path = Path(path)
        if not path.exists():
            return None

        spec = importlib.util.spec_from_file_location(
            f"custom_module_{path.stem}", str(path)
        )
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find CustomModule subclass
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and issubclass(attr, CustomModule)
                    and attr is not CustomModule
                ):
                    return attr

        return None
    except Exception:
        return None


def create_module_instance(
    name: str, client: Any = None, **kwargs: Any
) -> CustomModule | None:
    """Create an instance of a registered module by name."""
    module_class = _module_registry.get(name)
    if module_class:
        return module_class(client=client, **kwargs)
    return None


# Built-in example modules

class WordPressScanner(CustomModule):
    """Example: Scan for common WordPress vulnerabilities."""

    name = "wordpress"
    description = "Scan for common WordPress issues"
    author = "EvidenceGuardian"
    version = "1.0.0"

    WP_PATHS = [
        "/wp-admin/",
        "/wp-login.php",
        "/wp-content/",
        "/wp-includes/",
        "/wp-config.php",
        "/wp-config.php.bak",
        "/xmlrpc.php",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
    ]

    def run(self, target: ScanTarget) -> list[Finding]:
        import httpx

        _lazy_import()
        findings = []
        client = self.client or httpx.Client(timeout=10.0, follow_redirects=True)

        for path in self.WP_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    evidence = Evidence(
                        finding_id=_next_finding_id("WP"),
                        title=f"WordPress path found: {path}",
                        description=f"WordPress path {path} is accessible.",
                        request=HttpRequest(method="GET", url=url),
                        response=HttpResponse(status_code=200, body=resp.text[:300]),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.INFORMATION_DISCLOSURE,
                        severity=Severity.LOW,
                        endpoint=url,
                        parameter="n/a",
                        summary=f"WordPress path: {path}",
                        confidence=0.90,
                        evidence=evidence,
                    ))
            except Exception:
                continue

        return findings


class DrupalScanner(CustomModule):
    """Example: Scan for common Drupal vulnerabilities."""

    name = "drupal"
    description = "Scan for common Drupal issues"
    author = "EvidenceGuardian"
    version = "1.0.0"

    DRUPAL_PATHS = [
        "/user/login",
        "/admin/",
        "/sites/default/settings.php",
        "/sites/default/files/",
        "/cron.php",
        "/update.php",
        "/xmlrpc.php",
    ]

    def run(self, target: ScanTarget) -> list[Finding]:
        import httpx

        _lazy_import()
        findings = []
        client = self.client or httpx.Client(timeout=10.0, follow_redirects=True)

        for path in self.DRUPAL_PATHS:
            url = f"{target.url.rstrip('/')}{path}"
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    evidence = Evidence(
                        finding_id=_next_finding_id("DRUPAL"),
                        title=f"Drupal path found: {path}",
                        description=f"Drupal path {path} is accessible.",
                        request=HttpRequest(method="GET", url=url),
                        response=HttpResponse(status_code=200, body=resp.text[:300]),
                    )
                    findings.append(Finding(
                        id=evidence.finding_id,
                        type=VulnType.INFORMATION_DISCLOSURE,
                        severity=Severity.LOW,
                        endpoint=url,
                        parameter="n/a",
                        summary=f"Drupal path: {path}",
                        confidence=0.90,
                        evidence=evidence,
                    ))
            except Exception:
                continue

        return findings


# Register built-in custom modules
register_module(WordPressScanner)
register_module(DrupalScanner)