"""Scanner orchestrator — runs all vulnerability modules and collects findings."""
from __future__ import annotations

import time
from typing import Any

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from .core import Finding, ScanResult, ScanTarget
from .llm import LLMClient
from .vulns.ssrf import SSRFModule
from .vulns.idor import IDORModule
from .vulns.xss import XSSModule
from .vulns.sqli import SQLiModule
from .vulns.open_redirect import OpenRedirectModule
from .vulns.sensitive_data import SensitiveDataExposureModule
from .vulns.misconfiguration import SecurityMisconfigurationModule

console = Console()


class Scanner:
    """Main scanner that orchestrates all vulnerability modules."""

    def __init__(
        self,
        llm: LLMClient | None = None,
        modules: list[str] | None = None,
    ):
        self.llm = llm or LLMClient()
        self.modules = modules or ["ssrf", "idor", "xss", "sqli", "open_redirect", "sensitive_data", "misconfiguration"]

    def scan(self, target: ScanTarget) -> ScanResult:
        """Run a full scan against the target."""
        result = ScanResult(
            target=target,
            llm_backend=self.llm.backend,
        )

        # Validate target is in scope before starting
        if not target.is_in_scope(target.url):
            console.print(f"[red]Target {target.url} is not in scope![/red]")
            result.end_time = time.time()
            return result
        redirect_client = httpx.Client(timeout=15.0, follow_redirects=False)
        # All other modules can follow redirects normally
        client = httpx.Client(timeout=15.0, follow_redirects=True)

        # Initialize all modules
        module_instances = {
            "ssrf": SSRFModule(client=client, llm=self.llm),
            "idor": IDORModule(client=client),
            "xss": XSSModule(client=client),
            "sqli": SQLiModule(client=client),
            "open_redirect": OpenRedirectModule(client=redirect_client),
            "sensitive_data": SensitiveDataExposureModule(client=client),
            "misconfiguration": SecurityMisconfigurationModule(client=client),
        }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            total_tasks = len(self.modules)
            task = progress.add_task("Scanning...", total=total_tasks)

            for module_name in self.modules:
                progress.update(task, description=f"Running {module_name}...")
                module = module_instances.get(module_name)
                if module:
                    try:
                        findings = module.run(target)
                        result.findings.extend(findings)
                        result.modules_run.append(module_name)
                    except Exception as e:
                        console.print(f"[red]Module {module_name} failed: {e}[/red]")
                progress.advance(task)

        client.close()
        result.end_time = time.time()

        # Run LLM analysis on findings
        if result.findings:
            self._enrich_with_llm(target, result)

        return result

    def _enrich_with_llm(self, target: ScanTarget, result: ScanResult):
        """Use LLM to add context and confidence scoring to findings."""
        findings_text = "\n".join(
            f"- {f.id}: {f.type.value} at {f.endpoint} (confidence: {f.confidence})"
            for f in result.findings
        )

        prompt = f"""Analyze these security findings for {target.url}:

{findings_text}

For each finding, provide:
1. A refined confidence score (0.0-1.0)
2. A recommended remediation
3. The potential impact

Output as JSON: {{"findings": [{{"id": "...", "confidence": 0.9, "remediation": "...", "impact": "..."}}]}}"""

        try:
            llm_output = self.llm.analyze(
                prompt,
                system="You are a security expert analyzing vulnerability findings. Be precise and honest."
            )
            # Parse and apply enrichment
            parsed = self.llm.parse_findings(llm_output)
            enrichment_map = {f.get("id"): f for f in parsed if isinstance(f, dict)}

            for finding in result.findings:
                enrichment = enrichment_map.get(finding.id)
                if enrichment:
                    if "remediation" in enrichment and finding.evidence:
                        finding.evidence.metadata["remediation"] = enrichment["remediation"]
                    if "impact" in enrichment and finding.evidence:
                        finding.evidence.metadata["impact"] = enrichment["impact"]
        except Exception as e:
            console.print(f"[yellow]LLM enrichment skipped: {e}[/yellow]")

    def print_summary(self, result: ScanResult):
        """Print a rich terminal summary of the scan results."""
        console.print()
        console.print("=" * 60)
        console.print("[bold cyan]EvidenceGuardian Scan Report[/bold cyan]")
        console.print("=" * 60)
        console.print(f"Target: [bold]{result.target.url}[/bold]")
        console.print(f"Duration: {result.duration_seconds:.1f}s")
        console.print(f"Modules: {', '.join(result.modules_run)}")
        console.print(f"LLM: {result.llm_backend}")

        if not result.findings:
            console.print("\n[green]No findings detected.[/green]")
            return

        console.print(f"\n[bold]Findings: {len(result.findings)} total, "
                      f"{result.proven_count} proven[/bold]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("ID", style="dim")
        table.add_column("Type")
        table.add_column("Severity")
        table.add_column("Endpoint")
        table.add_column("Proven", justify="center")

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for f in result.findings:
            color = severity_colors.get(f.severity.value, "white")
            proven_mark = "[green]✓[/green]" if f.is_proven else "[red]✗[/red]"
            table.add_row(
                f.id,
                f.type.value,
                f"[{color}]{f.severity.value.upper()}[/{color}]",
                f.endpoint[:40],
                proven_mark,
            )

        console.print(table)
        console.print()

        # Detail view for proven findings
        proven = [f for f in result.findings if f.is_proven]
        if proven:
            console.print("[bold green]Proven Findings (with evidence):[/bold green]\n")
            for f in proven:
                console.print(f"  [cyan]{f.id}[/cyan]: {f.summary}")
                if f.evidence:
                    console.print(f"    Request: {f.evidence.request.method} {f.evidence.request.url}")
                    if f.evidence.response:
                        console.print(f"    Response: {f.evidence.response.status_code}")
                    if f.evidence.proof_script:
                        console.print(f"    [dim]PoC script available[/dim]")
                console.print()
