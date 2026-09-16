"""Webhook notifier for scan findings."""
from __future__ import annotations

import json
import os
from typing import Any

from .reporter import HTMLReporter
from .core import ScanResult


class WebhookNotifier:
    """Send scan results to configured webhooks."""

    def __init__(self, webhook_urls: list[str] | None = None):
        self.webhook_urls = list(webhook_urls) if webhook_urls else []  # Don't mutate caller's list
        # Support env var for CI/CD
        env_webhooks = os.environ.get("EVIDENCE_GUARDIAN_WEBHOOKS", "")
        if env_webhooks:
            self.webhook_urls.extend(env_webhooks.split(","))

    def notify(self, result: ScanResult) -> list[dict[str, Any]]:
        """Send findings to all configured webhooks."""
        if not self.webhook_urls:
            return []

        payload = self._build_payload(result)
        results = []

        for url in self.webhook_urls:
            url = url.strip()
            if not url:
                continue
            try:
                response = self._send_webhook(url, payload)
                results.append({"url": url, "status": response.get("status", "unknown")})
            except Exception as e:
                results.append({"url": url, "status": "error", "error": str(e)})

        return results

    def _build_payload(self, result: ScanResult) -> dict[str, Any]:
        """Build webhook payload."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in result.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        return {
            "tool": "EvidenceGuardian",
            "target": result.target.url,
            "scan_duration_seconds": result.duration_seconds,
            "total_findings": len(result.findings),
            "proven_findings": result.proven_count,
            "severity_counts": severity_counts,
            "findings": [
                {
                    "id": f.id,
                    "type": f.type.value,
                    "severity": f.severity.value,
                    "endpoint": f.endpoint,
                    "summary": f.summary,
                    "confidence": f.confidence,
                    "is_proven": f.is_proven,
                }
                for f in result.findings
            ],
            "modules_run": result.modules_run,
            "llm_backend": result.llm_backend,
        }

    def _send_webhook(self, url: str, payload: dict) -> dict[str, Any]:
        """Send webhook to URL (supports Slack, Discord, generic)."""
        import requests

        # Detect webhook type from URL
        if "slack.com" in url:
            slack_payload = self._format_slack(payload)
            resp = requests.post(url, json=slack_payload, timeout=30)
        elif "discord.com" in url:
            discord_payload = self._format_discord(payload)
            resp = requests.post(url, json=discord_payload, timeout=30)
        else:
            resp = requests.post(url, json=payload, timeout=30)

        return {"status": resp.status_code, "response": resp.text[:200]}

    def _format_slack(self, payload: dict) -> dict[str, Any]:
        """Format payload for Slack incoming webhook."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": " EvidenceGuardian Scan Complete",
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target:*\n{payload['target']}"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{payload['scan_duration_seconds']:.1f}s"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{payload['total_findings']} total, {payload['proven_findings']} proven"},
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Critical:*\n{payload['severity_counts'].get('critical', 0)}"},
                    {"type": "mrkdwn", "text": f"*High:*\n{payload['severity_counts'].get('high', 0)}"},
                    {"type": "mrkdwn", "text": f"*Medium:*\n{payload['severity_counts'].get('medium', 0)}"},
                    {"type": "mrkdwn", "text": f"*Low:*\n{payload['severity_counts'].get('low', 0)}"},
                ]
            },
        ]

        return {"blocks": blocks}

    def _format_discord(self, payload: dict) -> dict[str, Any]:
        """Format payload for Discord webhook."""
        embeds = [
            {
                "title": "EvidenceGuardian Scan Complete",
                "color": 0xFF0000 if payload["severity_counts"].get("critical", 0) > 0 else 0xFFA500,
                "fields": [
                    {"name": "Target", "value": payload["target"], "inline": True},
                    {"name": "Findings", "value": f"{payload['total_findings']} total", "inline": True},
                    {"name": "Critical", "value": str(payload["severity_counts"].get("critical", 0)), "inline": True},
                    {"name": "High", "value": str(payload["severity_counts"].get("high", 0)), "inline": True},
                ],
            }
        ]

        return {"embeds": embeds}