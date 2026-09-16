"""HTML reporter — generates self-contained evidence bundles."""
from __future__ import annotations

import base64
import html
import json
import os
from datetime import datetime
from typing import Any

from jinja2 import Template

from .core import Finding, ScanResult

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvidenceGuardian Report — {{ target_url }}</title>
    <style>
        :root {
            --bg: #0d1117;
            --surface: #161b22;
            --border: #30363d;
            --text: #c9d1d9;
            --text-dim: #8b949e;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #da3633;
            --medium: #d29922;
            --low: #1f6feb;
            --info: #8b949e;
            --proven: #3fb950;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }
        h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
        .meta { color: var(--text-dim); font-size: 0.9rem; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1.2rem;
            text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { color: var(--text-dim); font-size: 0.85rem; }
        .finding {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .finding-header {
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
        }
        .finding-body { padding: 1.5rem; }
        .severity {
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical { background: var(--critical); color: white; }
        .severity-high { background: var(--high); color: white; }
        .severity-medium { background: var(--medium); color: black; }
        .severity-low { background: var(--low); color: white; }
        .severity-info { background: var(--info); color: white; }
        .proven-badge {
            background: var(--proven);
            color: black;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .evidence-section {
            margin-top: 1rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border);
        }
        .evidence-title {
            color: var(--accent);
            font-weight: bold;
            margin-bottom: 0.5rem;
        }
        pre {
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1rem;
            overflow-x: auto;
            font-size: 0.85rem;
            line-height: 1.4;
        }
        .request-response {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-top: 0.5rem;
        }
        .confidence { color: var(--text-dim); font-size: 0.9rem; }
        .endpoint { font-family: monospace; color: var(--accent); }
        .remediation {
            background: rgba(88, 166, 255, 0.1);
            border-left: 3px solid var(--accent);
            padding: 0.75rem 1rem;
            margin-top: 0.5rem;
            border-radius: 0 4px 4px 0;
        }
        footer {
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 0.85rem;
            text-align: center;
        }
        @media (max-width: 768px) {
            .request-response { grid-template-columns: 1fr; }
            body { padding: 1rem; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>EvidenceGuardian Report</h1>
            <div class="meta">
                <p>Target: <span class="endpoint">{{ target_url }}</span></p>
                <p>Generated: {{ generated_at }}</p>
                <p>Duration: {{ duration_seconds }}s | Modules: {{ modules|join(', ') }} | LLM: {{ llm_backend }}</p>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" style="color: var(--accent)">{{ total_findings }}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--proven)">{{ proven_count }}</div>
                <div class="stat-label">Proven</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--critical)">{{ severity_counts.critical }}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--high)">{{ severity_counts.high }}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" style="color: var(--medium)">{{ severity_counts.medium }}</div>
                <div class="stat-label">Medium</div>
            </div>
        </div>

        <h2 style="margin-bottom: 1rem;">Findings</h2>

        {% for finding in findings %}
        <div class="finding">
            <div class="finding-header">
                <div>
                    <strong>{{ finding.id }}</strong> — {{ finding.type }}
                    <span class="severity severity-{{ finding.severity }}">{{ finding.severity }}</span>
                </div>
                {% if finding.is_proven %}
                <span class="proven-badge">PROVEN</span>
                {% endif %}
            </div>
            <div class="finding-body">
                <p><strong>Endpoint:</strong> <span class="endpoint">{{ finding.endpoint }}</span></p>
                <p><strong>Parameter:</strong> {{ finding.parameter }}</p>
                <p><strong>Summary:</strong> {{ finding.summary }}</p>
                <p class="confidence"><strong>Confidence:</strong> {{ "%.0f"|format(finding.confidence * 100) }}%</p>

                {% if finding.evidence %}
                <div class="evidence-section">
                    <div class="evidence-title">Evidence</div>
                    <p>{{ finding.evidence.description }}</p>

                    {% if finding.evidence.request %}
                    <div class="request-response">
                        <div>
                            <div class="evidence-title">Request</div>
                            <pre>{{ finding.evidence.request.method }} {{ finding.evidence.request.url }}</pre>
                        </div>
                        <div>
                            <div class="evidence-title">Response</div>
                            <pre>Status: {{ finding.evidence.response.status_code }}
Time: {{ "%.0f"|format(finding.evidence.response.response_time_ms) }}ms
{{ finding.evidence.response.body[:500] }}</pre>
                        </div>
                    </div>
                    {% endif %}

                    {% if finding.evidence.proof_script %}
                    <div class="evidence-section">
                        <div class="evidence-title">Proof of Concept</div>
                        <pre>{{ finding.evidence.proof_script }}</pre>
                    </div>
                    {% endif %}

                    {% if finding.evidence.metadata.get('remediation') %}
                    <div class="remediation">
                        <strong>Remediation:</strong> {{ finding.evidence.metadata.remediation }}
                    </div>
                    {% endif %}

                    {% if finding.evidence.metadata.get('impact') %}
                    <div class="remediation" style="border-left-color: var(--high);">
                        <strong>Impact:</strong> {{ finding.evidence.metadata.impact }}
                    </div>
                    {% endif %}
                </div>
                {% endif %}
            </div>
        </div>
        {% endfor %}

        <footer>
            <p>Generated by EvidenceGuardian v{{ version }} — AI-native security research framework</p>
            <p>Every finding includes reproducible evidence. No proof, no claim.</p>
        </footer>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Generate self-contained HTML evidence bundles."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir

    def generate(self, result: ScanResult) -> str:
        """Generate an HTML report and return the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        template = Template(REPORT_TEMPLATE)

        # Count severities
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        html_content = template.render(
            target_url=result.target.url,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=f"{result.duration_seconds:.1f}",
            modules=result.modules_run,
            llm_backend=result.llm_backend,
            total_findings=len(result.findings),
            proven_count=result.proven_count,
            severity_counts=severity_counts,
            findings=result.findings,
            version="0.1.0",
        )

        # Write file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = result.target.url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")[:30]
        filename = f"evidence_guardian_{safe_target}_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath
