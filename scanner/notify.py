from __future__ import annotations

from pathlib import Path
from typing import Optional

import requests

from scanner.engine import Finding, ScanResult

RC_FILENAME = ".leakscanrc"
_TIMEOUT = 5
_MAX_ITEMS = 10

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Discord embed colors (decimal RGB) and Slack-side severity emoji.
SEVERITY_COLOR_HEX = {
    "CRITICAL": 0xC0392B,
    "HIGH": 0xE74C3C,
    "MEDIUM": 0xF1C40F,
    "LOW": 0x95A5A6,
}
SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":red_circle:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":white_circle:",
}
CLEAN_COLOR_HEX = 0x2ECC71


def _rc_path(path: Optional[Path] = None) -> Path:
    return path or (Path.home() / RC_FILENAME)


def load_rc(path: Optional[Path] = None) -> dict[str, str]:
    """Load simple KEY="VALUE" pairs from ~/.leakscanrc.

    Returns an empty dict if the file does not exist or can't be read.
    Used to store webhook URLs so they don't need to be passed on the
    command line every time.
    """
    rc_path = _rc_path(path)
    config: dict[str, str] = {}
    if not rc_path.is_file():
        return config
    try:
        for line in rc_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            config[key.strip().upper()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return config


def save_webhook(kind: str, url: str, path: Optional[Path] = None) -> Path:
    """Persist a webhook URL to ~/.leakscanrc, creating or updating the file."""
    rc_path = _rc_path(path)
    config = load_rc(rc_path)
    key = "SLACK_WEBHOOK_URL" if kind == "slack" else "DISCORD_WEBHOOK_URL"
    config[key] = url
    lines = [f'{k}="{v}"' for k, v in config.items()]
    rc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return rc_path


def resolve_webhook(kind: str, explicit: Optional[str]) -> Optional[str]:
    """Return the webhook URL to use: an explicit CLI value, or one saved in ~/.leakscanrc."""
    if explicit:
        return explicit
    key = "SLACK_WEBHOOK_URL" if kind == "slack" else "DISCORD_WEBHOOK_URL"
    return load_rc().get(key) or None


def _severity_counts(result: ScanResult) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in result.findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _summary_line(counts: dict[str, int]) -> str:
    parts = [f"{n} {sev}" for sev, n in counts.items() if n]
    return ", ".join(parts) if parts else "0 findings"


def _top_findings(findings: list[Finding], limit: int = _MAX_ITEMS) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line_number))
    return ordered[:limit]


def build_slack_payload(result: ScanResult, target: str, clean: bool = False) -> dict:
    """Build a Slack Block Kit message body for an incoming webhook."""
    if clean or not result.findings:
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "leakscan: all clear"}},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"Scanned *{target}*: {result.files_scanned} file(s), 0 secrets found.",
                    },
                },
            ]
        }

    counts = _severity_counts(result)
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"leakscan found {len(result.findings)} secret(s)"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Target:* {target}\n*Summary:* {_summary_line(counts)}",
            },
        },
        {"type": "divider"},
    ]

    top = _top_findings(result.findings)
    for f in top:
        emoji = SEVERITY_EMOJI.get(f.severity, "")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *[{f.severity}] {f.secret_type}*\n`{f.file}:{f.line_number}`",
            },
        })

    remaining = len(result.findings) - len(top)
    if remaining > 0:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"...and {remaining} more finding(s)."}],
        })

    return {"blocks": blocks}


def build_discord_payload(result: ScanResult, target: str, clean: bool = False) -> dict:
    """Build a Discord embed message body for a webhook."""
    if clean or not result.findings:
        return {
            "embeds": [{
                "title": "leakscan: all clear",
                "description": f"Scanned **{target}**: {result.files_scanned} file(s), 0 secrets found.",
                "color": CLEAN_COLOR_HEX,
            }]
        }

    counts = _severity_counts(result)
    top_severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(s)), "LOW")
    color = SEVERITY_COLOR_HEX.get(top_severity, CLEAN_COLOR_HEX)

    top = _top_findings(result.findings)
    fields = [
        {
            "name": f"[{f.severity}] {f.secret_type}",
            "value": f"`{f.file}:{f.line_number}`",
            "inline": False,
        }
        for f in top
    ]

    embed = {
        "title": f"leakscan found {len(result.findings)} secret(s)",
        "description": f"**Target:** {target}\n**Summary:** {_summary_line(counts)}",
        "color": color,
        "fields": fields,
    }

    remaining = len(result.findings) - len(top)
    if remaining > 0:
        embed["footer"] = {"text": f"...and {remaining} more finding(s)."}

    return {"embeds": [embed]}


def _post(webhook_url: str, payload: dict) -> bool:
    try:
        r = requests.post(webhook_url, json=payload, timeout=_TIMEOUT)
        return r.status_code < 300
    except Exception:
        return False


def send_notifications(
    result: ScanResult,
    target: str,
    notify: Optional[str],
    slack_webhook: Optional[str] = None,
    discord_webhook: Optional[str] = None,
    notify_clean: bool = False,
) -> list[str]:
    """Send Slack and/or Discord webhook notifications for a scan result.

    Returns a list of human-readable status messages (one per webhook
    attempted) for the caller to display. Never raises: network errors
    and missing webhook URLs are reported as messages, not exceptions.
    """
    if not notify:
        return []

    if not result.findings and not notify_clean:
        return []

    kinds = []
    if notify in ("slack", "both"):
        kinds.append("slack")
    if notify in ("discord", "both"):
        kinds.append("discord")

    messages: list[str] = []
    for kind in kinds:
        explicit = slack_webhook if kind == "slack" else discord_webhook
        url = resolve_webhook(kind, explicit)
        if not url:
            flag = "--slack-webhook" if kind == "slack" else "--discord-webhook"
            messages.append(
                f"--notify {kind} requested but no webhook URL is configured "
                f"(pass {flag} or save one to ~/.leakscanrc)."
            )
            continue

        clean = not result.findings
        payload = (
            build_slack_payload(result, target, clean=clean)
            if kind == "slack"
            else build_discord_payload(result, target, clean=clean)
        )

        if _post(url, payload):
            messages.append(f"Sent {kind} notification.")
        else:
            messages.append(f"Failed to send {kind} notification (request error or non-2xx response).")

    return messages
