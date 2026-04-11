import fnmatch
import os
import re
from pathlib import Path

IGNORE_FILENAME = ".secretignore"

DEFAULT_IGNORES = [
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.bin", "*.exe",
    "*.lock", "*.sum",
    ".git/**", "node_modules/**", "__pycache__/**", ".venv/**",
    "*.pyc", "*.pyo",
]


def _glob_to_regex(pattern: str) -> re.Pattern:
    parts = pattern.replace("\\", "/").split("/")
    regex_parts = []
    for part in parts:
        if part == "**":
            regex_parts.append(".*")
        else:
            regex_parts.append(re.escape(part).replace(r"\*", "[^/]*").replace(r"\?", "[^/]"))
    return re.compile("^" + "/".join(regex_parts) + "$")


def _matches(rel_str: str, pattern: str) -> bool:
    normalized = rel_str.replace("\\", "/")
    name = normalized.split("/")[-1]

    if "**" not in pattern and "/" not in pattern:
        return fnmatch.fnmatch(name, pattern)

    if "**" in pattern:
        try:
            return bool(_glob_to_regex(pattern).match(normalized))
        except re.error:
            return False

    return fnmatch.fnmatch(normalized, pattern)


def load_ignore_patterns(root: Path) -> list[str]:
    patterns = list(DEFAULT_IGNORES)
    ignore_file = root / IGNORE_FILENAME
    if ignore_file.exists():
        with open(ignore_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    return patterns


def is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path

    rel_str = str(relative)

    for pattern in patterns:
        if _matches(rel_str, pattern):
            return True

    return False
