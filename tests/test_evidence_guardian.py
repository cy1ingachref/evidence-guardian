"""Tests for EvidenceGuardian — verifies each module detects demo vulnerabilities."""
from __future__ import annotations

import os
import sys
import time
import subprocess
import pytest
import httpx

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evidence_guardian.core import ScanResult, ScanTarget, Severity, VulnType
from evidence_guardian.llm import LLMClient
from evidence_guardian.vulns.ssrf import SSRFModule
from evidence_guardian.vulns.idor import IDORModule
from evidence_guardian.vulns.xss import XSSModule
from evidence_guardian.vulns.sqli import SQLiModule
from evidence_guardian.vulns.open_redirect import OpenRedirectModule
from evidence_guardian.scanner import Scanner
from evidence_guardian.reporter import HTMLReporter


# --- Fixtures ---

@pytest.fixture(scope="session")
def demo_server():
    """Start the vulnerable Flask app for integration tests."""
    demo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo", "vulnerable_app.py")
    proc = subprocess.Popen(
        [sys.executable, demo_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait for server
    for _ in range(30):
        try:
            httpx.get("http://127.0.0.1:5000/", timeout=1)
            break
        except Exception:
            time.sleep(0.3)
    yield "http://127.0.0.1:5000"
    proc.terminate()
    proc.wait()


@pytest.fixture
def target(demo_server):
    return ScanTarget(
        url=demo_server,
        scope_description="Test target",
    )


@pytest.fixture
def http_client():
    return httpx.Client(timeout=10.0, follow_redirects=True)


# --- LLM Tests ---

class TestLLMClient:
    def test_mock_mode_detection(self):
        llm = LLMClient(mock=True)
        assert llm.mock_mode is True
        assert "mock" in llm.backend.lower()

    def test_analyze_returns_findings(self):
        llm = LLMClient(mock=True)
        result = llm.analyze("Analyze SSRF vulnerability in url parameter")
        assert "findings" in result

    def test_parse_findings(self):
        llm = LLMClient(mock=True)
        raw = '{"findings": [{"id": "EG-TEST-001", "type": "SSRF", "severity": "high"}]}'
        parsed = llm.parse_findings(raw)
        assert len(parsed) == 1
        assert parsed[0]["id"] == "EG-TEST-001"

    def test_parse_findings_from_markdown(self):
        llm = LLMClient(mock=True)
        raw = 'Here are findings:\n```json\n{"findings": [{"id": "EG-001"}]}\n```'
        parsed = llm.parse_findings(raw)
        assert len(parsed) == 1


# --- Core Tests ---

class TestCore:
    def test_scan_target_scope(self):
        target = ScanTarget(url="https://example.com", scope_description="test")
        assert target.is_in_scope("https://example.com/api/users")
        assert not target.is_in_scope("https://evil.com/api/users")

    def test_scan_target_disallowed_paths(self):
        target = ScanTarget(
            url="https://example.com",
            scope_description="test",
            disallowed_paths=["/admin", "/internal"],
        )
        assert not target.is_in_scope("https://example.com/admin")
        assert target.is_in_scope("https://example.com/public")

    def test_finding_proven_with_evidence(self):
        from evidence_guardian.core import Finding, Evidence, HttpRequest, HttpResponse
        evidence = Evidence(
            finding_id="EG-001",
            title="Test",
            description="Test evidence",
            request=HttpRequest(method="GET", url="http://x"),
            response=HttpResponse(status_code=200),
        )
        finding = Finding(
            id="EG-001",
            type=VulnType.SSRF,
            severity=Severity.HIGH,
            endpoint="/api/test",
            parameter="url",
            summary="Test",
            confidence=0.9,
            evidence=evidence,
        )
        assert finding.is_proven is True

    def test_finding_unproven_without_evidence(self):
        from evidence_guardian.core import Finding
        finding = Finding(
            id="EG-002",
            type=VulnType.XSS,
            severity=Severity.MEDIUM,
            endpoint="/search",
            parameter="q",
            summary="Test",
            confidence=0.5,
        )
        assert finding.is_proven is False

    def test_scan_result_stats(self):
        target = ScanTarget(url="https://example.com", scope_description="test")
        result = ScanResult(target=target)
        assert result.proven_count == 0
        assert result.unproven_count == 0


# --- Module Integration Tests (require demo_server) ---

class TestSSRFModule:
    def test_detects_ssrf_in_fetch_endpoint(self, target, http_client):
        llm = LLMClient(mock=True)
        mod = SSRFModule(client=http_client, llm=llm)
        findings = mod.run(target)
        # Should find at least one SSRF finding
        ssrf_findings = [f for f in findings if f.type == VulnType.SSRF]
        assert len(ssrf_findings) >= 1, f"Expected SSRF findings, got: {[f.id for f in findings]}"
        # At least one should have evidence
        assert any(f.is_proven for f in ssrf_findings)


class TestIDORModule:
    def test_detects_idor_in_user_endpoint(self, target, http_client):
        mod = IDORModule(client=http_client)
        findings = mod.run(target)
        idor_findings = [f for f in findings if f.type == VulnType.IDOR]
        assert len(idor_findings) >= 1, f"Expected IDOR findings, got: {[f.id for f in findings]}"
        assert any(f.is_proven for f in idor_findings)


class TestXSSModule:
    def test_detects_xss_in_search(self, target, http_client):
        mod = XSSModule(client=http_client)
        findings = mod.run(target)
        xss_findings = [f for f in findings if f.type == VulnType.XSS]
        assert len(xss_findings) >= 1, f"Expected XSS findings, got: {[f.id for f in findings]}"


class TestSQLiModule:
    def test_detects_sqli_in_login(self, target, http_client):
        mod = SQLiModule(client=http_client)
        findings = mod.run(target)
        sqli_findings = [f for f in findings if f.type == VulnType.SQLI]
        assert len(sqli_findings) >= 1, f"Expected SQLi findings, got: {[f.id for f in findings]}"


class TestOpenRedirectModule:
    def test_detects_open_redirect(self, target):
        # Need client with follow_redirects=False for this module
        mod = OpenRedirectModule()
        findings = mod.run(target)
        redir_findings = [f for f in findings if f.type == VulnType.OPEN_REDIRECT]
        assert len(redir_findings) >= 1, f"Expected redirect findings, got: {[f.id for f in findings]}"


# --- Scanner Integration ---

class TestScanner:
    def test_full_scan(self, target):
        llm = LLMClient(mock=True)
        scanner = Scanner(llm=llm)
        result = scanner.scan(target)
        assert len(result.findings) > 0
        assert result.proven_count > 0
        assert "ssrf" in result.modules_run

    def test_scan_requires_scope(self, target):
        # Scanner should only test in-scope URLs
        target.allowed_hosts = ["allowed-host.com"]
        scanner = Scanner(llm=LLMClient(mock=True), modules=["ssrf"])
        result = scanner.scan(target)
        # All findings should be in scope (none since host doesn't match)
        assert len(result.findings) == 0


# --- Reporter Tests ---

class TestReporter:
    def test_generates_html_report(self, tmp_path):
        target = ScanTarget(url="https://example.com", scope_description="test")
        result = ScanResult(target=target, llm_backend="test")
        
        from evidence_guardian.core import Finding, Evidence, HttpRequest, HttpResponse
        evidence = Evidence(
            finding_id="EG-TEST-001",
            title="Test Finding",
            description="This is a test",
            request=HttpRequest(method="GET", url="https://example.com/test"),
            response=HttpResponse(status_code=200, body="response body"),
            proof_script="print('poc')",
        )
        finding = Finding(
            id="EG-TEST-001",
            type=VulnType.SSRF,
            severity=Severity.HIGH,
            endpoint="https://example.com/test",
            parameter="url",
            summary="Test summary",
            confidence=0.9,
            evidence=evidence,
        )
        result.findings.append(finding)
        result.end_time = result.start_time + 5.0

        reporter = HTMLReporter(output_dir=str(tmp_path))
        path = reporter.generate(result)
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "EG-TEST-001" in content

        assert "PROVEN" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
