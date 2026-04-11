import fnmatch
import os
from pathlib import Path

IGNORE_FILENAME = ".secretignore"

DEFAULT_IGNORES = [
    "*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg",
    "*.pdf", "*.zip", "*.tar", "*.gz", "*.bin", "*.exe",
    "*.lock", "*.sum",
    ".git/*", "node_modules/*", "__pycache__/*", ".venv/*",
    "*.pyc", "*.pyo",
]


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
    name = path.name

    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
        if fnmatch.fnmatch(rel_str, pattern):
            return True
        if pattern.endswith("/*"):
            dir_part = pattern[:-2]
            if rel_str.startswith(dir_part + os.sep) or rel_str.startswith(dir_part + "/"):
                return True
    return False
