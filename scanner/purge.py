from __future__ import annotations

from typing import Optional

FORCE_PUSH_WARNING = """\
WARNING: rewriting history changes every commit hash after the rewrite
point. Anyone with a clone of this repo will need to re-clone or hard
reset to the new history. Coordinate with your team before pushing, and
push with --force-with-lease (never plain --force) so you do not silently
overwrite commits someone else has pushed in the meantime:

    git push --force-with-lease origin <branch>
"""

ROTATION_REMINDER = """\
Rewriting history does NOT undo a leak. Anyone who already cloned, forked,
or scraped this repository (including automated bots) may still have a
copy of the old commits. Rotate every exposed credential at its provider
BEFORE or immediately after rewriting history. Run `leakscan scan . --verify`
to check whether the leaked secrets are still live.
"""

USAGE_TEXT = """\
leakscan purge generates (but does not run) commands to remove secrets
from your git history using git filter-repo or BFG Repo-Cleaner.

Choose one of:
  --file <path>     Remove a specific file from all of git history.
  --commit <sha>    Show what a specific commit changed, so you can
                     target those files or values for removal.
  --all             Generate a template for redacting one or more
                     secret values everywhere they appear in history.

Use --method filter-repo or --method bfg to show commands for only one
tool (both are shown by default).

Examples:
  leakscan purge --file config/secrets.yaml
  leakscan purge --commit a1b2c3d4
  leakscan purge --all
  leakscan purge --file .env --method filter-repo
"""

_INSTALL_NOTE = {
    "filter-repo": (
        "git filter-repo (https://github.com/newren/git-filter-repo) is a "
        "fast, actively maintained history-rewriting tool. Install with:\n"
        "  pip install git-filter-repo\n"
    ),
    "bfg": (
        "BFG Repo-Cleaner (https://rtyley.github.io/bfg-repo-cleaner/) is a "
        "Java tool that is often faster than filter-repo for large repos "
        "with many big files. Install with:\n"
        "  brew install bfg   # or download the jar and run: java -jar bfg.jar\n"
    ),
}


def _section(title: str, body: str) -> str:
    bar = "-" * len(title)
    return f"{title}\n{bar}\n{body}"


def _file_commands(path: str, method: Optional[str]) -> list[str]:
    sections = []
    if method in (None, "filter-repo"):
        sections.append(_section(
            "git filter-repo",
            f"{_INSTALL_NOTE['filter-repo']}\n"
            f"Remove '{path}' from every commit in history:\n\n"
            f"  git filter-repo --path {path} --invert-paths --force\n",
        ))
    if method in (None, "bfg"):
        sections.append(_section(
            "BFG Repo-Cleaner",
            f"{_INSTALL_NOTE['bfg']}\n"
            f"Remove '{path}' from every commit in history:\n\n"
            f"  bfg --delete-files {path.split('/')[-1]}\n"
            f"  git reflog expire --expire=now --all\n"
            f"  git gc --prune=now --aggressive\n",
        ))
    return sections


def _commit_commands(sha: str, method: Optional[str]) -> list[str]:
    sections = [_section(
        "Find what this commit changed",
        f"  git show --stat {sha}\n\n"
        "Use the file paths above with `leakscan purge --file <path>` to\n"
        "remove a whole file, or use --replace-text below to redact a\n"
        "specific secret value wherever it appears in history.\n",
    )]
    if method in (None, "filter-repo"):
        sections.append(_section(
            "git filter-repo (redact a value everywhere)",
            f"{_INSTALL_NOTE['filter-repo']}\n"
            "Create a replacements file with the leaked value(s):\n\n"
            "  echo '<secret-value>==>REDACTED' > replacements.txt\n\n"
            "Then rewrite history, replacing every occurrence:\n\n"
            "  git filter-repo --replace-text replacements.txt --force\n",
        ))
    if method in (None, "bfg"):
        sections.append(_section(
            "BFG Repo-Cleaner (redact a value everywhere)",
            f"{_INSTALL_NOTE['bfg']}\n"
            "Create a text file with one secret value per line:\n\n"
            "  echo '<secret-value>' > secrets.txt\n\n"
            "Then rewrite history, replacing every occurrence:\n\n"
            "  bfg --replace-text secrets.txt\n"
            "  git reflog expire --expire=now --all\n"
            "  git gc --prune=now --aggressive\n",
        ))
    return sections


def _all_commands(method: Optional[str]) -> list[str]:
    sections = []
    if method in (None, "filter-repo"):
        sections.append(_section(
            "git filter-repo (redact every leaked value)",
            f"{_INSTALL_NOTE['filter-repo']}\n"
            "List every secret value found by leakscan, one replacement per\n"
            "line, in replacements.txt (format: <secret-value>==>REDACTED):\n\n"
            "  leakscan scan . --format json -o findings.json\n"
            "  # build replacements.txt from findings.json, one line per secret:\n"
            "  #   <secret-value-1>==>REDACTED\n"
            "  #   <secret-value-2>==>REDACTED\n\n"
            "Then rewrite the entire history in one pass:\n\n"
            "  git filter-repo --replace-text replacements.txt --force\n",
        ))
    if method in (None, "bfg"):
        sections.append(_section(
            "BFG Repo-Cleaner (redact every leaked value)",
            f"{_INSTALL_NOTE['bfg']}\n"
            "List every secret value found by leakscan, one per line, in\n"
            "secrets.txt, then rewrite the entire history in one pass:\n\n"
            "  bfg --replace-text secrets.txt\n"
            "  git reflog expire --expire=now --all\n"
            "  git gc --prune=now --aggressive\n",
        ))
    return sections


def build_purge_report(
    commit: Optional[str] = None,
    file: Optional[str] = None,
    purge_all: bool = False,
    method: Optional[str] = None,
) -> str:
    """Build the text output for `leakscan purge`.

    Returns plain text describing filter-repo and/or BFG commands to
    remove secrets from git history. Nothing here is executed; it is
    informational output for the user to review and run themselves.
    """
    if not (commit or file or purge_all):
        return USAGE_TEXT

    parts: list[str] = []

    if file:
        parts.extend(_file_commands(file, method))
    if commit:
        parts.extend(_commit_commands(commit, method))
    if purge_all:
        parts.extend(_all_commands(method))

    parts.append(_section("Before you push", FORCE_PUSH_WARNING))
    parts.append(_section("Rotate your credentials", ROTATION_REMINDER))

    return "\n\n".join(parts)


PURGE_REMINDER = "Run 'leakscan purge --help' to generate history cleanup commands."
