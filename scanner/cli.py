from __future__ import annotations

import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from scanner.engine import (
    ScanResult,
    scan_content_string,
    scan_git_history,
    scan_patch_string,
    scan_path,
)
from scanner.github.fetcher import GitHubFetcher, RateLimitError
from scanner import reporter

console = Console()
err_console = Console(stderr=True)

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _parse_github_url(value: str) -> tuple[str, str] | None:
    m = _GITHUB_URL_RE.match(value.strip())
    return (m.group(1), m.group(2)) if m else None


@click.group()
def cli():
    """Secret Scanner — detect leaked API keys and tokens in code."""
    pass


@cli.command()
@click.argument("path", default=".", required=False)
@click.option("--github", "-g", default=None, metavar="USERNAME",
              help="Scan all public repos for a GitHub user/org.")
@click.option("--repo", "-r", default=None, metavar="REPO",
              help="Limit GitHub scan to a specific repo name.")
@click.option("--token", "-t", default=None, envvar="GITHUB_TOKEN",
              metavar="TOKEN", help="GitHub personal access token (or set GITHUB_TOKEN).")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["terminal", "json", "csv", "sarif", "disclosure"]),
              default="terminal", show_default=True)
@click.option("--output", "-o", default=None, metavar="FILE")
@click.option("--entropy-threshold", default=4.5, show_default=True)
@click.option("--no-entropy", is_flag=True, default=False)
@click.option("--severity", "-s",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
              default=None)
@click.option("--history", is_flag=True, default=False,
              help="Also scan git history for secrets in past commits.")
@click.option("--depth", default=None, type=int, metavar="N",
              help="Commits to scan with --history (default: 100 local, 50 GitHub).")
@click.option("--since", default=None, metavar="DATE",
              help="Limit history scan to commits after DATE (e.g. 2024-01-01).")
@click.option("--branch", default=None, metavar="BRANCH",
              help="Limit history scan to a specific branch (local only).")
@click.option("--verify", is_flag=True, default=False,
              help="Verify whether found secrets are still live via API calls.")
@click.option("--baseline", default=None, metavar="FILE",
              help="Filter out findings already in this baseline file.")
@click.option("--save-baseline", default=None, metavar="FILE",
              help="Save current findings as a baseline for future runs.")
@click.option("--redact", is_flag=True, default=False,
              help="Redact secret values in all output (show first/last 4 chars only).")
@click.option("--include-gists", is_flag=True, default=False,
              help="Include GitHub Gists in --github scans.")
def scan(
    path: str,
    github: Optional[str],
    repo: Optional[str],
    token: Optional[str],
    output_format: str,
    output: Optional[str],
    entropy_threshold: float,
    no_entropy: bool,
    severity: Optional[str],
    history: bool,
    depth: Optional[int],
    since: Optional[str],
    branch: Optional[str],
    verify: bool,
    baseline: Optional[str],
    save_baseline: Optional[str],
    redact: bool,
    include_gists: bool,
):
    """Scan a local PATH, GitHub repo URL, or GitHub profile for leaked secrets.

    \b
    Examples:
      secrets scan ./myproject
      secrets scan . --history --since 2024-01-01
      secrets scan https://github.com/owner/repo --verify
      secrets scan --github username --include-gists
      secrets scan . --baseline .secrets.baseline
    """
    gh_owner: Optional[str] = None
    gh_repo_filter: Optional[str] = None

    if github:
        gh_owner = github
        gh_repo_filter = repo
    else:
        url_match = _parse_github_url(path)
        if url_match:
            gh_owner, gh_repo_filter = url_match

    if gh_owner:
        result = _scan_github(
            username=gh_owner,
            repo_filter=gh_repo_filter,
            token=token,
            entropy_threshold=entropy_threshold,
            no_entropy=no_entropy,
            history=history,
            depth=depth or 50,
            include_gists=include_gists,
        )
    else:
        target = Path(path).resolve()
        if not target.exists():
            err_console.print(f"[red]Path not found:[/red] {target}")
            sys.exit(1)

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=err_console, transient=True) as progress:
            progress.add_task(f"Scanning {target}...", total=None)
            result = scan_path(target, entropy_threshold, no_entropy)

        if history:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                          console=err_console, transient=True) as progress:
                progress.add_task("Scanning git history...", total=None)
                hist = scan_git_history(
                    target, entropy_threshold, no_entropy,
                    depth=depth or 100, since=since, branch=branch,
                )
            result.findings.extend(hist.findings)
            result.commits_scanned = hist.commits_scanned
            result.errors.extend(hist.errors)

    if baseline:
        bpath = Path(baseline)
        if bpath.exists():
            from scanner.baseline import load, filter_new
            known = load(bpath)
            before = len(result.findings)
            result.findings = filter_new(result.findings, known)
            suppressed = before - len(result.findings)
            if suppressed:
                err_console.print(f"[dim]Suppressed {suppressed} baseline finding(s).[/dim]")
        else:
            err_console.print(f"[yellow]Baseline file not found:[/yellow] {bpath}")

    if severity:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = order[severity]
        result.findings = [f for f in result.findings if order.get(f.severity, 9) <= threshold]

    if verify and result.findings:
        _verify_findings(result)

    if save_baseline:
        from scanner.baseline import save
        save(result, Path(save_baseline))
        err_console.print(f"[green]Baseline saved to:[/green] {save_baseline}")

    if output_format == "terminal":
        reporter.print_terminal(result, redact=redact)
    elif output_format == "json":
        _write(reporter.to_json(result, redact=redact), output)
    elif output_format == "csv":
        _write(reporter.to_csv(result, redact=redact), output)
    elif output_format == "sarif":
        _write(reporter.to_sarif(result), output)
    elif output_format == "disclosure":
        target_name = gh_owner or github
        if not target_name:
            err_console.print("[red]--format disclosure requires --github <username> or a GitHub URL[/red]")
            sys.exit(1)
        _write(reporter.to_disclosure_report(target_name, result, redact=redact), output)

    _exit_code(result)


def _verify_findings(result: ScanResult) -> None:
    from scanner.verifier import verify, can_verify
    verifiable = [f for f in result.findings if can_verify(f)]
    if not verifiable:
        return
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=err_console, transient=True) as progress:
        task = progress.add_task(f"Verifying {len(verifiable)} secret(s)...", total=len(verifiable))
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(verify, f): f for f in verifiable}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    f.verified = future.result()
                except Exception:
                    pass
                progress.advance(task)


def _scan_github(
    username: str,
    repo_filter: Optional[str],
    token: Optional[str],
    entropy_threshold: float,
    no_entropy: bool,
    history: bool = False,
    depth: int = 50,
    include_gists: bool = False,
) -> ScanResult:
    fetcher = GitHubFetcher(token=token)
    result = ScanResult()

    if history and not token:
        err_console.print("[yellow]Warning: --history without --token hits GitHub rate limits fast.[/yellow]")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=err_console, transient=True) as progress:
        task = progress.add_task(f"Fetching repos for {username}...", total=None)

        try:
            repos = [f"{username}/{repo_filter}"] if repo_filter else fetcher.list_repos(username)
        except RateLimitError as e:
            err_console.print(f"[red]Rate limited.[/red] Retry in {e.wait_seconds}s")
            sys.exit(1)
        except Exception as e:
            err_console.print(f"[red]GitHub API error:[/red] {e}")
            sys.exit(1)

        progress.update(task, description=f"Scanning {len(repos)} repos...")

        for repo_name in repos:
            progress.update(task, description=f"Scanning {repo_name}...")
            try:
                for repo_file in fetcher.iter_repo_files(repo_name):
                    result.findings.extend(scan_content_string(
                        content=repo_file.content,
                        filepath=f"{repo_file.repo}/{repo_file.path}",
                        entropy_threshold=entropy_threshold,
                        no_entropy=no_entropy,
                    ))
                    result.files_scanned += 1
            except RateLimitError as e:
                err_console.print(f"\n[yellow]Rate limited. Waiting {e.wait_seconds}s...[/yellow]")
                time.sleep(e.wait_seconds + 2)
            except Exception as e:
                result.errors.append(f"{repo_name}: {e}")
                result.files_skipped += 1

            if history:
                seen: set[tuple] = set()
                progress.update(task, description=f"Scanning {repo_name} history...")
                try:
                    for sha, filepath, patch in fetcher.iter_commit_diffs(repo_name, depth):
                        for f in scan_patch_string(patch, filepath, sha, entropy_threshold, no_entropy):
                            key = (f.matched_value, f.secret_type)
                            if key not in seen:
                                seen.add(key)
                                result.findings.append(f)
                except RateLimitError as e:
                    err_console.print(f"\n[yellow]Rate limited on history. Waiting {e.wait_seconds}s...[/yellow]")
                    time.sleep(e.wait_seconds + 2)
                except Exception as e:
                    result.errors.append(f"{repo_name} history: {e}")

        if include_gists:
            progress.update(task, description=f"Scanning gists for {username}...")
            try:
                gists = fetcher.list_gists(username)
                for gist_id in gists:
                    progress.update(task, description=f"Scanning gist:{gist_id[:8]}...")
                    try:
                        for gist_file in fetcher.iter_gist_files(gist_id):
                            result.findings.extend(scan_content_string(
                                content=gist_file.content,
                                filepath=f"{gist_file.repo}/{gist_file.path}",
                                entropy_threshold=entropy_threshold,
                                no_entropy=no_entropy,
                            ))
                            result.files_scanned += 1
                    except Exception as e:
                        result.errors.append(f"gist:{gist_id}: {e}")
            except RateLimitError as e:
                err_console.print(f"\n[yellow]Rate limited on gists. Waiting {e.wait_seconds}s...[/yellow]")
            except Exception as e:
                result.errors.append(f"gists: {e}")

    return result


def _write(content: str, filepath: Optional[str]) -> None:
    if filepath:
        Path(filepath).write_text(content, encoding="utf-8")
        err_console.print(f"[green]Output written to:[/green] {filepath}")
    else:
        click.echo(content)


def _exit_code(result: ScanResult) -> None:
    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in result.findings)
    sys.exit(1 if has_critical else 0)


@cli.command(name="install-hook")
def install_hook():
    """Install a pre-commit git hook in the current repo."""
    hook_path = Path(".git/hooks/pre-commit")
    if not Path(".git").exists():
        err_console.print("[red]Not a git repository.[/red]")
        sys.exit(1)

    hook_path.write_text("""#!/bin/sh
BASELINE_ARG=""
if [ -f .secrets.baseline ]; then
  BASELINE_ARG="--baseline .secrets.baseline"
fi
secrets scan . --severity HIGH --format terminal $BASELINE_ARG
if [ $? -ne 0 ]; then
  echo ""
  echo "Commit blocked: secrets detected."
  echo "Run 'secrets scan .' for full details."
  echo "To suppress a known false positive, add '# nosec' to the line."
  exit 1
fi
""")
    hook_path.chmod(0o755)
    console.print("[green]Pre-commit hook installed at .git/hooks/pre-commit[/green]")


if __name__ == "__main__":
    cli()
