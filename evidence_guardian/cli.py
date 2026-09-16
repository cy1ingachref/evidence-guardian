"""CLI — rich terminal interface for EvidenceGuardian."""
from __future__ import annotations

import os
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from . import __version__
from .core import ScanTarget
from .llm import LLMClient
from .scanner import Scanner
from .reporter import HTMLReporter

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="evidence-guardian")
def cli():
    """EvidenceGuardian — AI security research with reproducible evidence.

    Every finding must carry proof. No proof, no claim.
    """
    pass


@cli.command()
@click.argument("url")
@click.option("--scope", "-s", default="Default scope", help="Scope description for the scan")
@click.option("--modules", "-m", default="ssrf,idor,xss,sqli,open_redirect,sensitive_data,misconfiguration",
              help="Comma-separated list of modules to run")
@click.option("--output", "-o", default="reports", help="Output directory for reports")
@click.option("--mock/--no-mock", default=None,
              help="Force mock LLM mode (no API key needed)")
@click.option("--open/--no-open", "open_report", default=False,
              help="Open the HTML report after scan")
def scan(url: str, scope: str, modules: str, output: str, mock: bool | None, open_report: bool):
    """Run a security scan against a target URL.

    Example:

        evidence-guardian scan https://example.com --scope "Only test /api/* endpoints"
    """
    # Validate URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Build target
    target = ScanTarget(
        url=url,
        scope_description=scope,
    )

    # Confirm authorization
    console.print(Panel(
        f"[bold]Target:[/bold] {url}\n"
        f"[bold]Scope:[/bold] {scope}\n"
        f"[bold]Modules:[/bold] {modules}\n\n"
        "[yellow]You must have explicit authorization to scan this target.[/yellow]",
        title="EvidenceGuardian",
        border_style="cyan",
    ))

    if not mock:
        confirm = Prompt.ask("Do you have authorization to scan this target?", choices=["yes", "no"], default="no")
        if confirm != "yes":
            console.print("[red]Scan cancelled. Authorization required.[/red]")
            sys.exit(1)

    # Initialize LLM
    llm = LLMClient(mock=mock)
    console.print(f"[dim]LLM backend: {llm.backend}[/dim]")

    # Parse modules
    module_list = ["ssrf", "idor", "xss", "sqli", "open_redirect", "sensitive_data", "misconfiguration"]
    if modules:
        module_list = [m.strip() for m in modules.split(",")]

    # Run scan
    scanner = Scanner(llm=llm, modules=module_list)
    result = scanner.scan(target)

    # Print summary
    scanner.print_summary(result)

    # Generate report
    if result.findings:
        reporter = HTMLReporter(output_dir=output)
        report_path = reporter.generate(result)
        console.print(f"[green]Report saved to: {report_path}[/green]")

        if open_report:
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
    else:
        console.print("[yellow]No findings to report.[/yellow]")


@cli.command()
@click.argument("report_path", type=click.Path(exists=True))
def view(report_path: str):
    """View an existing HTML report in the browser."""
    import webbrowser
    webbrowser.open(f"file://{os.path.abspath(report_path)}")
    console.print(f"[green]Opened: {report_path}[/green]")


@cli.command()
def demo():
    """Run a demo scan against a local vulnerable Flask app."""
    console.print(Panel(
        "[bold]EvidenceGuardian Demo Mode[/bold]\n\n"
        "This will:\n"
        "1. Start a local vulnerable Flask app\n"
        "2. Run a full scan against it\n"
        "3. Generate an HTML evidence report\n\n"
        "[dim]No external targets. No API key needed.[/dim]",
        border_style="green",
    ))

    # Check if Flask is available
    try:
        import flask
    except ImportError:
        console.print("[red]Flask is required for the demo. Install with: pip install flask[/red]")
        sys.exit(1)

    # Start demo server in background
    import subprocess
    import time

    # Use the packaged demo app (works after pip install)
    demo_dir = os.path.join(os.path.dirname(__file__), "demo")
    demo_script = os.path.join(demo_dir, "vulnerable_app.py")
    if not os.path.exists(demo_script):
        console.print(f"[red]Demo app not found at {demo_script}[/red]")
        sys.exit(1)

    console.print("[dim]Starting demo server...[/dim]")
    proc = subprocess.Popen(
        [sys.executable, demo_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for server to start
    time.sleep(2)

    try:
        # Run scan
        target = ScanTarget(
            url="http://127.0.0.1:5000",
            scope_description="Local demo — authorized test target",
        )
        llm = LLMClient(mock=True)
        scanner = Scanner(llm=llm)
        result = scanner.scan(target)
        scanner.print_summary(result)

        # Generate report
        if result.findings:
            reporter = HTMLReporter(output_dir="reports")
            report_path = reporter.generate(result)
            console.print(f"\n[green bold]Demo report saved to: {report_path}[/green bold]")
            console.print("[dim]Open it in your browser to see the full evidence bundle.[/dim]")

            # Try to open
            import webbrowser
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
    finally:
        proc.terminate()
        proc.wait()


@cli.command()
def info():
    """Show information about the current configuration."""
    llm = LLMClient()
    console.print(Panel(
        f"[bold]EvidenceGuardian v0.1.0[/bold]\n\n"
        f"LLM Backend: [cyan]{llm.backend}[/cyan]\n"
        f"API Key Set: {'[green]Yes[/green]' if llm.api_key else '[yellow]No (using mock mode)[/yellow]'}\n\n"
        f"Available modules:\n"
        f"  • ssrf — Server-Side Request Forgery\n"
        f"  • idor — Insecure Direct Object Reference\n"
        f"  • xss — Cross-Site Scripting\n"
        f"  • sqli — SQL Injection\n"
        f"  • open_redirect — Open Redirect\n",
        title="Configuration",
        border_style="cyan",
    ))


if __name__ == "__main__":
    cli()
