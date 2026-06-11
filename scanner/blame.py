from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class BlameInfo:
    commit: str
    author_email: str
    author_date: str
    age_seconds: float
    branch: Optional[str]
    message: str

    @property
    def age_human(self) -> str:
        return format_age(self.age_seconds)


def _run_git(root: Path, args: list[str], timeout: int = 10) -> Optional[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except Exception:
        return None


def is_git_repo(root: Path) -> bool:
    out = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return out is not None and out.strip() == "true"


def get_current_branch(root: Path) -> Optional[str]:
    out = _run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    if not out:
        return None
    branch = out.strip()
    return None if branch in ("", "HEAD") else branch


def get_blame_info(root: Path, filepath: str, line_number: int) -> Optional[BlameInfo]:
    """Return blame info for a single line of a tracked file.

    Returns None if the path is not inside a git repo, the file is
    untracked or has uncommitted changes on this line, or git blame
    otherwise fails. Callers should treat None as "no blame data
    available" rather than an error.
    """
    out = _run_git(
        root,
        ["blame", "-L", f"{line_number},{line_number}", "--porcelain", "--", filepath],
    )
    if not out:
        return None

    lines = out.splitlines()
    if not lines:
        return None

    header = lines[0].split()
    if not header:
        return None
    commit = header[0]
    if set(commit) == {"0"}:
        # All-zero SHA: uncommitted/staged change, nothing to blame yet.
        return None

    info: dict[str, str] = {}
    for line in lines[1:]:
        if line.startswith("\t"):
            break
        for key in ("author-mail", "author-time", "summary"):
            prefix = key + " "
            if line.startswith(prefix):
                info[key] = line[len(prefix):]

    author_time = info.get("author-time")
    if author_time is None:
        return None
    try:
        ts = float(author_time)
    except ValueError:
        return None

    author_mail = info.get("author-mail", "").strip("<>")
    message = info.get("summary", "")
    age_seconds = max(0.0, time.time() - ts)
    author_date = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))

    return BlameInfo(
        commit=commit[:12],
        author_email=author_mail,
        author_date=author_date,
        age_seconds=age_seconds,
        branch=get_current_branch(root),
        message=message,
    )


def format_age(age_seconds: float) -> str:
    """Format a duration in seconds as a short human-readable age (e.g. '3d', '2h', '5mo')."""
    seconds = int(age_seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h"
    days = hours // 24
    if days < 30:
        return f"{days}d"
    months = days // 30
    if months < 12:
        return f"{months}mo"
    years = days // 365
    return f"{years}y"


# Scraping-probability risk thresholds, based on how long a secret has
# been visible in git history.
SCRAPING_RISK_THRESHOLDS = {
    "LOW": "under 1 hour",
    "MEDIUM": "1 to 24 hours",
    "HIGH": "24 hours to 30 days",
    "CRITICAL": "over 30 days",
}


def scraping_risk(age_seconds: float) -> str:
    """Classify the probability this secret has been scraped by automated bots."""
    hours = age_seconds / 3600
    if hours < 1:
        return "LOW"
    if hours < 24:
        return "MEDIUM"
    if hours < 24 * 30:
        return "HIGH"
    return "CRITICAL"


def scraping_warning(age_seconds: float) -> Optional[str]:
    """Return an escalating warning string for old secrets, or None if not warranted."""
    days = age_seconds / 86400
    if days > 90:
        return (
            "This secret has been in git history for over 90 days. "
            "ASSUME COMPROMISED: rotate it immediately regardless of whether "
            "you have observed any suspicious activity."
        )
    if days > 30:
        return (
            "This secret has been in git history for over 30 days. "
            "HIGH probability it has already been scraped by automated bots "
            "that continuously crawl public repositories for credentials."
        )
    return None
