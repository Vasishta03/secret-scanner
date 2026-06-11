from __future__ import annotations

import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from tqdm import tqdm

from scanner.engine import (
    Finding,
    ScanResult,
    scan_content_string,
    scan_git_history,
    scan_patch_string,
    scan_path,
    scan_staged,
)
from scanner.engine import DEFAULT_CHUNK_SIZE, DEFAULT_MAX_FILE_SIZE
from scanner.github.fetcher import GitHubFetcher, RateLimitError
from scanner.config import load_config
from scanner import blame as blameutil
from scanner import notify, reporter
from scanner import purge as purge_module
from scanner.ignorefile import append_ignore_pattern, write_init_template

console = Console()
err_console = Console(stderr=True)

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def _parse_github_url(value: str) -> tuple[str, str] | None:
    m = _GITHUB_URL_RE.match(value.strip())
    return (m.group(1), m.group(2)) if m else None


_STREAM_STYLE = {
    "CRITICAL": {"fg": "red", "bold": True},
    "HIGH": {"fg": "red"},
    "MEDIUM": {"fg": "yellow"},
    "LOW": {"fg": "white", "dim": True},
}


def _stream_finding(f: Finding, bar: Optional[tqdm]) -> None:
    style = _STREAM_STYLE.get(f.severity, {})
    tag = click.style(f.severity, **style)
    line = f"{tag}  {f.secret_type} - {f.file}:{f.line_number}"
    if bar is not None:
        bar.write(line)
    else:
        click.echo(line, err=True)


def _run_local_scan(
    target: Path,
    entropy_threshold: float,
    no_entropy: bool,
    threads: Optional[int],
    max_file_size: int,
    chunk_size: int,
    no_progress: bool,
    stream_live: bool,
) -> ScanResult:
    """Run a multi-threaded scan of a local path with a progress bar,
    a live stream of findings, and a benchmark summary at the end."""
    bar: Optional[tqdm] = None
    if not no_progress:
        bar = tqdm(
            total=None,
            unit="file",
            desc=f"Scanning {target}",
            file=sys.stderr,
            dynamic_ncols=True,
            leave=False,
        )

    def on_progress(done: int, total: int) -> None:
        if bar is not None:
            if bar.total != total:
                bar.total = total
                bar.refresh()
            bar.update(1)

    def on_finding(f: Finding) -> None:
        if stream_live:
            _stream_finding(f, bar)

    try:
        result = scan_path(
            target,
            entropy_threshold,
            no_entropy,
            threads=threads,
            max_file_size=max_file_size,
            chunk_size=chunk_size,
            on_finding=on_finding,
            on_progress=on_progress,
        )
    finally:
        if bar is not None:
            bar.close()

    err_console.print(
        f"[dim]Scanned {result.files_scanned} file(s) in {result.elapsed_seconds:.2f}s "
        f"({result.files_per_second:.1f} files/sec)[/dim]"
    )
    if result.large_files_skipped:
        for skipped in result.large_files_skipped:
            err_console.print(f"[yellow]Skipped (exceeds size limit):[/yellow] {skipped}")
    if result.binary_files_skipped:
        err_console.print(f"[dim]Skipped {result.binary_files_skipped} binary file(s)[/dim]")

    return result


def _attach_blame(result: ScanResult, root: Path) -> None:
    """Populate Finding.blame for findings in the working tree using `git blame`.

    Skipped for findings that already carry a commit (history-scan results,
    which point at the commit that introduced them rather than HEAD).
    """
    if not root.is_dir() or not blameutil.is_git_repo(root):
        return
    for f in result.findings:
        if f.commit:
            continue
        fp = Path(f.file)
        try:
            rel = str(fp.relative_to(root)) if fp.is_absolute() else f.file
        except ValueError:
            continue
        f.blame = blameutil.get_blame_info(root, rel, f.line_number)


@click.group()
def cli():
    """Secret Scanner - detect leaked API keys and tokens in code."""
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
@click.option("--staged", is_flag=True, default=False,
              help="Scan only git staged changes (for pre-commit use).")
@click.option("--config", "config_path", default=None, metavar="FILE",
              help="Path to .leakscan.yaml config file (auto-detected if omitted).")
@click.option("--baseline", default=None, metavar="FILE",
              help="Filter out findings already in this baseline file.")
@click.option("--save-baseline", default=None, metavar="FILE",
              help="Save current findings as a baseline for future runs.")
@click.option("--redact", is_flag=True, default=False,
              help="Redact secret values in all output (show first/last 4 chars only).")
@click.option("--include-gists", is_flag=True, default=False,
              help="Include GitHub Gists in --github scans.")
@click.option("--threads", default=None, type=int, metavar="N",
              help="Worker threads for scanning (default: CPU count).")
@click.option("--max-file-size", default=50, type=int, metavar="MB", show_default=True,
              help="Skip files larger than this size (in MB), with a warning.")
@click.option("--chunk-size", default=DEFAULT_CHUNK_SIZE, type=int, metavar="BYTES", show_default=True,
              help="Bytes read per chunk when scanning files (keeps memory flat on large repos).")
@click.option("--no-progress", is_flag=True, default=False,
              help="Disable the progress bar and live result stream.")
@click.option("--brief", is_flag=True, default=False,
              help="Compact one-line-per-finding output (default prints a full "
                   "blast-radius block for each finding).")
@click.option("--no-blame", is_flag=True, default=False,
              help="Skip git blame lookups (faster on large repos, no commit/age info).")
@click.option("--show-ignored", is_flag=True, default=False,
              help="List files skipped because of .leakscanignore patterns.")
@click.option("--notify", "notify_target", default=None,
              type=click.Choice(["slack", "discord", "both"]),
              help="Send a summary of results to Slack and/or Discord.")
@click.option("--webhook", default=None, metavar="URL",
              help="Webhook URL to use for --notify (overridden by --slack-webhook/--discord-webhook).")
@click.option("--slack-webhook", default=None, metavar="URL",
              help="Slack incoming webhook URL (overrides ~/.leakscanrc).")
@click.option("--discord-webhook", default=None, metavar="URL",
              help="Discord webhook URL (overrides ~/.leakscanrc).")
@click.option("--notify-clean", is_flag=True, default=False,
              help="Also send a notification when no secrets are found.")
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
    staged: bool,
    config_path: Optional[str],
    baseline: Optional[str],
    save_baseline: Optional[str],
    redact: bool,
    include_gists: bool,
    threads: Optional[int],
    max_file_size: int,
    chunk_size: int,
    no_progress: bool,
    brief: bool,
    no_blame: bool,
    show_ignored: bool,
    notify_target: Optional[str],
    webhook: Optional[str],
    slack_webhook: Optional[str],
    discord_webhook: Optional[str],
    notify_clean: bool,
):
    """Scan a local PATH, GitHub repo URL, or GitHub profile for leaked secrets.

    \b
    Examples:
      leakscan scan ./myproject
      leakscan scan . --staged
      leakscan scan . --history --since 2024-01-01
      leakscan scan https://github.com/owner/repo --verify
      leakscan scan --github username --include-gists
      leakscan scan . --baseline .secrets.baseline
      leakscan scan . --config custom-rules.yaml
      leakscan scan . --threads 16 --max-file-size 100
      leakscan scan . --brief --no-blame
      leakscan scan . --notify slack --slack-webhook https://hooks.slack.com/...
    """
    gh_owner: Optional[str] = None
    gh_repo_filter: Optional[str] = None

    # Load config from file or auto-detect
    target = Path(path).resolve()
    if config_path:
        cfg = load_config(Path(config_path).parent)
    else:
        cfg = load_config(target if target.is_dir() else target.parent)

    # Apply config overrides (CLI flags take precedence)
    if cfg.entropy_threshold is not None and entropy_threshold == 4.5:
        entropy_threshold = cfg.entropy_threshold
    if cfg.no_entropy is not None and not no_entropy:
        no_entropy = cfg.no_entropy
    if cfg.severity_threshold and not severity:
        severity = cfg.severity_threshold

    # Register custom patterns from config
    if cfg.custom_patterns:
        from scanner.patterns import PATTERNS
        PATTERNS.extend(cfg.custom_patterns)

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
    elif staged:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=err_console, transient=True) as progress:
            progress.add_task("Scanning staged changes...", total=None)
            result = scan_staged(target, entropy_threshold, no_entropy)
    else:
        target = Path(path).resolve()
        if not target.exists():
            err_console.print(f"[red]Path not found:[/red] {target}")
            sys.exit(1)

        result = _run_local_scan(
            target,
            entropy_threshold,
            no_entropy,
            threads=threads,
            max_file_size=max_file_size * 1_000_000,
            chunk_size=chunk_size,
            no_progress=no_progress,
            stream_live=(output_format == "terminal"),
        )

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

    if not gh_owner and not no_blame and not brief and result.findings:
        _attach_blame(result, target)

    if save_baseline:
        from scanner.baseline import save
        save(result, Path(save_baseline))
        err_console.print(f"[green]Baseline saved to:[/green] {save_baseline}")

    if show_ignored and result.ignored_files:
        err_console.print(f"\n[dim]Ignored {len(result.ignored_files)} file(s) (.leakscanignore):[/dim]")
        for ignored_path in result.ignored_files:
            err_console.print(f"[dim]  {ignored_path}[/dim]")

    if output_format == "terminal":
        reporter.print_terminal(result, redact=redact, brief=brief)
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

    if result.findings:
        err_console.print(f"\n[dim]{purge_module.PURGE_REMINDER}[/dim]")

    if notify_target:
        target_label = gh_owner or str(target)
        for message in notify.send_notifications(
            result,
            target_label,
            notify_target,
            slack_webhook=slack_webhook or webhook,
            discord_webhook=discord_webhook or webhook,
            notify_clean=notify_clean,
        ):
            err_console.print(f"[dim]{message}[/dim]")

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
leakscan scan . --staged --severity HIGH --format terminal --brief --no-blame $BASELINE_ARG
if [ $? -ne 0 ]; then
  echo ""
  echo "Commit blocked: secrets detected."
  echo "Run 'leakscan scan .' for full details."
  echo "To suppress a known false positive, add '# nosec' to the line."
  exit 1
fi
""")
    hook_path.chmod(0o755)
    console.print("[green]Pre-commit hook installed at .git/hooks/pre-commit[/green]")


@cli.command(name="ignore")
@click.argument("pattern")
@click.argument("path", default=".", required=False)
def ignore_cmd(pattern: str, path: str):
    """Add PATTERN to .leakscanignore (gitignore-style syntax).

    \b
    Examples:
      leakscan ignore "tests/"
      leakscan ignore "*.test.js"
      leakscan ignore "!important.env"
    """
    root = Path(path).resolve()
    ignore_file = append_ignore_pattern(root, pattern)
    console.print(f"[green]Added[/green] '{pattern}' to {ignore_file}")


@cli.command(name="init")
@click.argument("path", default=".", required=False)
def init_cmd(path: str):
    """Create a .leakscanignore file with sensible defaults in PATH."""
    root = Path(path).resolve()
    ignore_file, created = write_init_template(root)
    if created:
        console.print(f"[green]Created[/green] {ignore_file}")
    else:
        console.print(f"[yellow]Already exists:[/yellow] {ignore_file} (left unchanged)")


@cli.command()
@click.option("--commit", default=None, metavar="SHA",
              help="Show what a commit changed and how to redact its secrets from history.")
@click.option("--file", "file_", default=None, metavar="PATH",
              help="Remove a file from every commit in history.")
@click.option("--all", "purge_all", is_flag=True, default=False,
              help="Generate a template for redacting secret values everywhere they appear.")
@click.option("--method", default=None, type=click.Choice(["filter-repo", "bfg"]),
              help="Show commands for only one tool (default: both).")
def purge(commit: Optional[str], file_: Optional[str], purge_all: bool, method: Optional[str]):
    """Generate (but do not run) commands to remove secrets from git history.

    \b
    Examples:
      leakscan purge --file config/secrets.yaml
      leakscan purge --commit a1b2c3d4
      leakscan purge --all --method filter-repo
    """
    click.echo(purge_module.build_purge_report(commit=commit, file=file_, purge_all=purge_all, method=method))


if __name__ == "__main__":
    cli()
