"""Core framework — evidence types, scope gating, and evidence capture."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
from urllib.parse import urlparse


# Global counter for stable finding IDs
_finding_counter = 0


def _next_finding_id(prefix: str) -> str:
    """Generate a stable, unique finding ID.
    
    Uses a global counter + timestamp to avoid Python's randomized hash().
    """
    global _finding_counter
    _finding_counter += 1
    ts = int(time.time() * 1000) % 100000
    return f"EG-{prefix}-{ts:05d}-{_finding_counter:03d}"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    SSRF = "SSRF"
    IDOR = "IDOR"
    XSS = "XSS"
    SQLI = "SQLi"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"


@dataclass
class HttpRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HttpResponse:
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    response_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    """Reproducible proof of a finding."""
    finding_id: str
    title: str
    description: str
    request: HttpRequest | None = None
    response: HttpResponse | None = None
    proof_script: str | None = None
    screenshot_path: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_verifiable(self) -> bool:
        """Evidence is verifiable if it has a request+response pair or a proof script."""
        return (self.request is not None and self.response is not None) or \
               (self.proof_script is not None)

    def fingerprint(self) -> str:
        """Hash of the evidence for integrity verification."""
        content = f"{self.finding_id}:{self.title}:{self.description}"
        if self.request:
            content += f":{self.request.method}:{self.request.url}"
        if self.response:
            content += f":{self.response.status_code}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class Finding:
    """A security finding with attached evidence."""
    id: str
    type: VulnType
    severity: Severity
    endpoint: str
    parameter: str
    summary: str
    confidence: float  # 0.0 - 1.0
    evidence: Evidence | None = None
    timestamp: float = field(default_factory=time.time)

    @property
    def is_proven(self) -> bool:
        return self.evidence is not None and self.evidence.is_verifiable()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "summary": self.summary,
            "confidence": self.confidence,
            "is_proven": self.is_proven,
            "evidence_fingerprint": self.evidence.fingerprint() if self.evidence else None,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanTarget:
    """Authorized scan target with scope definition."""
    url: str
    scope_description: str
    allowed_hosts: list[str] = field(default_factory=list)
    disallowed_paths: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if not self.allowed_hosts:
            parsed = urlparse(self.url)
            self.allowed_hosts = [parsed.hostname]

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the authorized scope."""
        parsed = urlparse(url)
        # Must be same host
        if parsed.hostname not in self.allowed_hosts:
            return False
        # Must not be in disallowed paths
        for path in self.disallowed_paths:
            if parsed.path.startswith(path):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "scope": self.scope_description,
            "allowed_hosts": self.allowed_hosts,
            "disallowed_paths": self.disallowed_paths,
        }


@dataclass
class ScanResult:
    """Complete results of a scan."""
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    modules_run: list[str] = field(default_factory=list)
    llm_backend: str = "unknown"

    @property
    def duration_seconds(self) -> float:
        end = self.end_time or time.time()
        return end - self.start_time

    @property
    def proven_count(self) -> int:
        return sum(1 for f in self.findings if f.is_proven)

    @property
    def unproven_count(self) -> int:
        return sum(1 for f in self.findings if not f.is_proven)

    def by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {}
        for f in self.findings:
            sev = f.severity.value
            result.setdefault(sev, []).append(f)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "proven_count": self.proven_count,
            "unproven_count": self.unproven_count,
            "duration_seconds": self.duration_seconds,
            "modules_run": self.modules_run,
            "llm_backend": self.llm_backend,
        }
