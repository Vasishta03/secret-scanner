from __future__ import annotations

import hashlib
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from scanner.entropy import scan_line
from scanner.ignorefile import is_ignored, load_ignore_patterns
from scanner.patterns import PATTERNS

MAX_FILE_BYTES = 1_000_000
_ALLOWLIST_RE = re.compile(r"#\s*(?:nosec|gitleaks:allow|secretscanner:allow)\b", re.IGNORECASE)


@dataclass
class Finding:
    file: str
    line_number: int
    line: str
    secret_type: str
    severity: str
    matched_value: str
    entropy: Optional[float] = None
    source: str = "regex"
    commit: Optional[str] = None
    verified: Optional[str] = None

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.secret_type}:{self.matched_value}".encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    commits_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def _check_line(line: str, line_number: int, filepath: str, entropy_threshold: float) -> list[Finding]:
    if _ALLOWLIST_RE.search(line):
        return []
    findings = []
    for pattern in PATTERNS:
        match = pattern.regex.search(line)
        if match:
            findings.append(Finding(
                file=filepath,
                line_number=line_number,
                line=line.strip(),
                secret_type=pattern.name,
                severity=pattern.severity,
                matched_value=match.group(0)[:80],
                source="regex",
            ))
    has_regex = bool(findings)
    for ef in scan_line(line, line_number, threshold=entropy_threshold):
        if not has_regex:
            findings.append(Finding(
                file=filepath,
                line_number=line_number,
                line=line.strip(),
                secret_type="High Entropy String",
                severity="LOW",
                matched_value=ef.value[:80],
                entropy=ef.entropy,
                source="entropy",
            ))
    return findings


def _scan_content(content: str, filepath: str, entropy_threshold: float) -> list[Finding]:
    findings = []
    for i, line in enumerate(content.splitlines(), start=1):
        findings.extend(_check_line(line, i, filepath, entropy_threshold))
    return findings


def _iter_diff_additions(patch: str, filepath: str = None) -> Iterator[tuple[str, int, str]]:
    current_file = filepath
    current_line = 0
    in_hunk = False

    for line in patch.splitlines():
        if current_file is None and line.startswith("+++ b/"):
            current_file = line[6:]
            current_line = 0
            in_hunk = False
        elif line.startswith("diff --git ") or line.startswith("index ") or line.startswith("--- "):
            in_hunk = False
        elif line.startswith("@@ "):
            in_hunk = True
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1)) - 1
        elif in_hunk and line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            if current_file:
                yield current_file, current_line, line[1:]
        elif in_hunk and not line.startswith("-") and not line.startswith("\\"):
            current_line += 1


def _scan_file_worker(args: tuple) -> tuple[list[Finding] | None, str | None]:
    path, eff_threshold = args
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        return _scan_content(text, str(path), eff_threshold), None
    except Exception as e:
        return None, f"{path}: {e}"


def scan_path(root: Path, entropy_threshold: float = 4.5, no_entropy: bool = False) -> ScanResult:
    result = ScanResult()
    patterns = load_ignore_patterns(root)
    eff_threshold = entropy_threshold if not no_entropy else 999.0

    to_scan: list[Path] = []
    for path in _walk(root):
        if is_ignored(path, root, patterns):
            result.files_skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                result.files_skipped += 1
                continue
        except Exception:
            result.files_skipped += 1
            continue
        to_scan.append(path)

    with ThreadPoolExecutor(max_workers=8) as executor:
        for findings, error in executor.map(_scan_file_worker, [(p, eff_threshold) for p in to_scan]):
            if error:
                result.errors.append(error)
                result.files_skipped += 1
            else:
                result.findings.extend(findings)
                result.files_scanned += 1

    return result


def scan_content_string(
    content: str,
    filepath: str,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
) -> list[Finding]:
    eff_threshold = entropy_threshold if not no_entropy else 999.0
    return _scan_content(content, filepath, eff_threshold)


def scan_patch_string(
    patch: str,
    filepath: str,
    sha: str,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
) -> list[Finding]:
    eff_threshold = entropy_threshold if not no_entropy else 999.0
    findings = []
    for fp, line_num, line_content in _iter_diff_additions(patch, filepath=filepath):
        for f in _check_line(line_content, line_num, fp, eff_threshold):
            f.commit = sha[:12]
            findings.append(f)
    return findings


def scan_git_history(
    root: Path,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    depth: int = 100,
    since: Optional[str] = None,
    branch: Optional[str] = None,
) -> ScanResult:
    result = ScanResult()
    eff_threshold = entropy_threshold if not no_entropy else 999.0

    cmd = ["git", "-C", str(root), "log", "--format=%H"]
    if branch:
        cmd.append(branch)
    else:
        cmd.append("--all")
    cmd.append(f"-{depth}")
    if since:
        cmd.append(f"--since={since}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            result.errors.append("Not a git repository or git not available")
            return result
        commits = [c for c in proc.stdout.strip().splitlines() if c]
    except FileNotFoundError:
        result.errors.append("git not found in PATH")
        return result
    except Exception as e:
        result.errors.append(str(e))
        return result

    seen: set[tuple] = set()

    for sha in commits:
        try:
            proc = subprocess.run(
                ["git", "-C", str(root), "show", "--format=", "--unified=0", sha],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode != 0:
                result.files_skipped += 1
                continue
            for filepath, line_number, line_content in _iter_diff_additions(proc.stdout):
                for f in _check_line(line_content, line_number, filepath, eff_threshold):
                    key = (f.matched_value, f.secret_type)
                    if key not in seen:
                        seen.add(key)
                        f.commit = sha[:12]
                        result.findings.append(f)
            result.commits_scanned += 1
        except Exception as e:
            result.errors.append(f"{sha[:8]}: {e}")

    return result


def _walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file():
            yield path
