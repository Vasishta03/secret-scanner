from __future__ import annotations

import csv
import io
import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from scanner.blame import scraping_risk, scraping_warning
from scanner.engine import Finding, ScanResult
from scanner.remediation import get_remediation

console = Console(stderr=False)

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim white",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Colors used for the full per-finding blast-radius blocks (default output).
BLOCK_SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "white",
}

RISK_COLORS = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "red",
    "CRITICAL": "bold red",
}

VERIFIED_STYLE = {
    "LIVE":    ("[bold green]LIVE[/bold green]",    "bold green"),
    "REVOKED": ("[dim green]REVOKED[/dim green]",   "dim green"),
}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line_number))


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    keep = min(4, len(value) // 4)
    return value[:keep] + "*" * (len(value) - 2 * keep) + value[-keep:]


def _display(value: str, redact: bool) -> str:
    return _redact(value) if redact else value


def _blame_dict(f: Finding) -> Optional[dict]:
    if not f.blame:
        return None
    return {
        "commit": f.blame.commit,
        "author_email": f.blame.author_email,
        "author_date": f.blame.author_date,
        "age": f.blame.age_human,
        "branch": f.blame.branch,
        "scraping_risk": scraping_risk(f.blame.age_seconds),
    }


def print_terminal(result: ScanResult, redact: bool = False, brief: bool = False) -> None:
    findings = _sorted(result.findings)

    if not findings:
        console.print(Panel("[bold green]No secrets found.[/bold green]", expand=False))
        _print_summary(result)
        return

    if brief:
        _print_table(findings, redact)
    else:
        _print_blocks(findings, redact)

    _print_summary(result)


def _print_table(findings: list[Finding], redact: bool) -> None:
    has_commits = any(f.commit for f in findings)
    has_verified = any(f.verified for f in findings)

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold white", expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", style="cyan", no_wrap=False)
    table.add_column("File", style="blue", no_wrap=False)
    table.add_column("Line", style="white", width=6)
    table.add_column("Match", style="dim white", no_wrap=False)
    if has_commits:
        table.add_column("Commit", style="dim cyan", width=13, no_wrap=True)
    if has_verified:
        table.add_column("Status", width=9, no_wrap=True)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        entropy_tag = f" (H={f.entropy})" if f.entropy else ""
        display_val = _display(f.matched_value, redact)
        row = [
            Text(f.severity, style=color),
            f.secret_type + entropy_tag,
            f.file,
            str(f.line_number),
            display_val[:60] + ("..." if len(display_val) > 60 else ""),
        ]
        if has_commits:
            row.append(f.commit or "")
        if has_verified:
            v = f.verified
            if v == "LIVE":
                row.append(Text("LIVE", style="bold green"))
            elif v == "REVOKED":
                row.append(Text("REVOKED", style="dim green"))
            else:
                row.append(Text("?", style="dim"))
        table.add_row(*row)

    console.print(table)


def _print_blocks(findings: list[Finding], redact: bool) -> None:
    """Print one detailed block per finding: severity, location, match,
    blast-radius guidance, and (when available) git blame and secret age."""
    for f in findings:
        color = BLOCK_SEVERITY_STYLE.get(f.severity, "white")
        entropy_tag = f" (entropy {f.entropy})" if f.entropy else ""
        display_val = _display(f.matched_value, redact)

        console.print(f"[{color}]\\[{f.severity}][/{color}] [bold]{f.secret_type}[/bold]{entropy_tag}")
        console.print(f"  File: {f.file}:{f.line_number}")
        console.print(f"  Match: {display_val}")
        if f.commit:
            console.print(f"  Commit: {f.commit}")
        if f.verified == "LIVE":
            console.print("  Status: [bold green]LIVE[/bold green] (confirmed active via API)")
        elif f.verified == "REVOKED":
            console.print("  Status: [dim green]REVOKED[/dim green] (no longer active)")

        rem = get_remediation(f.secret_type)
        console.print(f"  If leaked: {rem.consequence}")
        console.print(f"  Blast radius: [bold]{rem.blast_radius}[/bold]")
        console.print(f"  Rotate at: {rem.rotation_url}")

        if f.blame:
            risk = scraping_risk(f.blame.age_seconds)
            risk_color = RISK_COLORS.get(risk, "white")
            console.print(
                f"  Git blame: {f.blame.author_email} - commit {f.blame.commit} "
                f"({f.blame.age_human} ago, branch {f.blame.branch or 'unknown'})"
            )
            console.print(f"    \"{f.blame.message}\"")
            console.print(
                f"  Secret age: {f.blame.age_human} - "
                f"scraping risk: [{risk_color}]{risk}[/{risk_color}]"
            )
            warning = scraping_warning(f.blame.age_seconds)
            if warning:
                console.print(f"  [bold red]{warning}[/bold red]")

        console.print()


def _print_summary(result: ScanResult) -> None:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            color = SEVERITY_COLORS[sev]
            parts.append(f"[{color}]{counts[sev]} {sev}[/{color}]")

    summary_str = "  ".join(parts) if parts else "[green]0 findings[/green]"
    scanned = f"{result.files_scanned} files"
    if result.commits_scanned:
        scanned += f" + {result.commits_scanned} commits"

    live = sum(1 for f in result.findings if f.verified == "LIVE")
    live_str = f"  [bold green]{live} LIVE[/bold green]" if live else ""

    console.print(
        f"\n[bold]Scanned:[/bold] {scanned}  "
        f"[bold]Skipped:[/bold] {result.files_skipped}  "
        f"[bold]Findings:[/bold] {summary_str}{live_str}"
    )
    if result.errors:
        console.print(f"[dim]Errors: {len(result.errors)}[/dim]")


def to_json(result: ScanResult, redact: bool = False) -> str:
    findings = _sorted(result.findings)
    return json.dumps(
        {
            "summary": {
                "files_scanned": result.files_scanned,
                "commits_scanned": result.commits_scanned,
                "files_skipped": result.files_skipped,
                "total_findings": len(findings),
                "by_severity": {
                    sev: sum(1 for f in findings if f.severity == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                },
            },
            "findings": [
                {
                    "severity": f.severity,
                    "type": f.secret_type,
                    "file": f.file,
                    "line": f.line_number,
                    "match": _display(f.matched_value, redact),
                    "entropy": f.entropy,
                    "source": f.source,
                    "commit": f.commit,
                    "verified": f.verified,
                    "fingerprint": f.fingerprint(),
                    "blast_radius": get_remediation(f.secret_type).blast_radius,
                    "rotation_url": get_remediation(f.secret_type).rotation_url,
                    "blame": _blame_dict(f),
                }
                for f in findings
            ],
        },
        indent=2,
    )


def to_csv(result: ScanResult, redact: bool = False) -> str:
    findings = _sorted(result.findings)
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=[
            "severity", "type", "file", "line", "match", "entropy", "source",
            "commit", "verified", "fingerprint", "blast_radius", "rotation_url",
            "secret_age", "scraping_risk",
        ],
    )
    writer.writeheader()
    for f in findings:
        rem = get_remediation(f.secret_type)
        blame_info = _blame_dict(f)
        writer.writerow({
            "severity": f.severity,
            "type": f.secret_type,
            "file": f.file,
            "line": f.line_number,
            "match": _display(f.matched_value, redact),
            "entropy": f.entropy or "",
            "source": f.source,
            "commit": f.commit or "",
            "verified": f.verified or "",
            "fingerprint": f.fingerprint(),
            "blast_radius": rem.blast_radius,
            "rotation_url": rem.rotation_url,
            "secret_age": blame_info["age"] if blame_info else "",
            "scraping_risk": blame_info["scraping_risk"] if blame_info else "",
        })
    return buf.getvalue()


def to_sarif(result: ScanResult) -> str:
    from scanner.patterns import PATTERNS
    findings = _sorted(result.findings)
    present_types = {f.secret_type for f in findings}
    pattern_map = {p.name: p for p in PATTERNS}

    rules = []
    for t in sorted(present_types):
        p = pattern_map.get(t)
        rules.append({
            "id": t,
            "name": t.replace(" ", ""),
            "shortDescription": {"text": p.description if p else t},
            "defaultConfiguration": {
                "level": _sarif_level(p.severity if p else "MEDIUM")
            },
            "helpUri": "https://github.com/Vasishta03/secret-scanner",
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secret-scanner",
                    "version": "0.4.0",
                    "informationUri": "https://github.com/Vasishta03/secret-scanner",
                    "rules": rules,
                }
            },
            "results": [
                {
                    "ruleId": f.secret_type,
                    "level": _sarif_level(f.severity),
                    "message": {"text": f"{f.secret_type} detected in {f.file}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": f.line_number},
                        }
                    }],
                    "partialFingerprints": {"primaryLocationLineHash": f.fingerprint()},
                    "properties": {
                        "blastRadius": get_remediation(f.secret_type).blast_radius,
                        "rotationUrl": get_remediation(f.secret_type).rotation_url,
                    },
                }
                for f in findings
            ],
        }],
    }
    return json.dumps(sarif, indent=2)


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(severity, "note")


def to_disclosure_report(username: str, result: ScanResult, redact: bool = False) -> str:
    findings = _sorted(result.findings)
    critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]

    lines = [
        "# Security Disclosure Report",
        "",
        f"**Target:** GitHub user `{username}`",
        f"**Findings:** {len(findings)} total ({len(critical_high)} critical/high)",
        "",
        "## Summary",
        "",
        "This report was generated by an automated secret scanner. "
        "The following potential secrets were detected in public repositories.",
        "",
        "## Findings",
        "",
    ]

    for f in findings:
        rem = get_remediation(f.secret_type)
        lines += [
            f"### [{f.severity}] {f.secret_type}",
            f"- **Repository/File:** `{f.file}`",
            f"- **Line:** {f.line_number}",
            f"- **Detected via:** {f.source}",
        ]
        if f.commit:
            lines.append(f"- **Commit:** `{f.commit}`")
        if f.verified:
            lines.append(f"- **Verified:** {f.verified}")
        if f.blame:
            lines.append(
                f"- **Last touched:** {f.blame.author_email} on {f.blame.author_date} "
                f"({f.blame.age_human} ago, commit `{f.blame.commit}`)"
            )
        lines += [
            f"- **Blast radius:** {rem.blast_radius}",
            "",
            f"**If leaked:** {rem.consequence}",
            "",
            f"**Recommendation:** Rotate this credential immediately at {rem.rotation_url} "
            "and audit access logs.",
            "",
        ]

    lines += [
        "## Recommended Actions",
        "",
        "1. Rotate all identified credentials immediately.",
        "2. Use environment variables or a secrets manager (e.g. Vault, AWS Secrets Manager).",
        "3. Add pre-commit hooks to prevent future leaks.",
        "4. Review git history - secrets committed then deleted are still visible.",
        "",
        "---",
        "*Report generated by [secret-scanner](https://github.com/Vasishta03/secret-scanner)*",
    ]

    return "\n".join(lines)
