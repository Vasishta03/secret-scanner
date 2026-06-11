from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, NamedTuple, Optional

from scanner.blame import BlameInfo
from scanner.entropy import scan_line
from scanner.ignorefile import is_ignored, load_ignore_patterns
from scanner.patterns import PATTERNS

# Files larger than this are skipped entirely (with a warning).
DEFAULT_MAX_FILE_SIZE = 50 * 1_000_000  # 50 MB

# Files are read in chunks of this size so memory stays flat regardless
# of file size. A trailing partial line ("leftover") is carried over to
# the next chunk so patterns are never split across a chunk boundary.
DEFAULT_CHUNK_SIZE = 1_000_000  # 1 MB

# First N bytes inspected to decide whether a file is binary.
_BINARY_SNIFF_BYTES = 8192

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
    blame: Optional[BlameInfo] = None

    def fingerprint(self) -> str:
        return hashlib.sha256(f"{self.secret_type}:{self.matched_value}".encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    commits_scanned: int = 0
    errors: list[str] = field(default_factory=list)
    binary_files_skipped: int = 0
    large_files_skipped: list[str] = field(default_factory=list)
    ignored_files: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    @property
    def files_per_second(self) -> float:
        if self.elapsed_seconds <= 0:
            return 0.0
        return self.files_scanned / self.elapsed_seconds


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


def _is_binary(path: Path) -> bool:
    """Treat a file as binary if its first chunk contains a NUL byte."""
    try:
        with open(path, "rb") as f:
            sniff = f.read(_BINARY_SNIFF_BYTES)
        return b"\x00" in sniff
    except Exception:
        return False


def _iter_lines_chunked(path: Path, chunk_size: int) -> Iterator[tuple[int, str]]:
    """Yield (line_number, line) pairs while reading the file in chunks.

    Memory stays proportional to chunk_size (plus one line) regardless
    of file size. A trailing partial line from one chunk ("leftover")
    is prepended to the next chunk so no pattern is ever split across
    a chunk boundary.
    """
    leftover = ""
    line_number = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            data = leftover + chunk
            lines = data.split("\n")
            leftover = lines.pop()
            for line in lines:
                line_number += 1
                yield line_number, line.rstrip("\r")

    if leftover:
        line_number += 1
        yield line_number, leftover.rstrip("\r")


class _FileScanResult(NamedTuple):
    path: str
    findings: Optional[list[Finding]]
    error: Optional[str]
    skip_reason: Optional[str]  # "large", "binary", or None


def _scan_file_worker(args: tuple) -> _FileScanResult:
    path, eff_threshold, max_file_size, chunk_size = args
    path_str = str(path)

    try:
        size = path.stat().st_size
    except Exception as e:
        return _FileScanResult(path_str, None, f"{path}: {e}", None)

    if size > max_file_size:
        return _FileScanResult(path_str, None, None, "large")

    if _is_binary(path):
        return _FileScanResult(path_str, None, None, "binary")

    try:
        findings: list[Finding] = []
        for line_number, line in _iter_lines_chunked(path, chunk_size):
            findings.extend(_check_line(line, line_number, path_str, eff_threshold))
        return _FileScanResult(path_str, findings, None, None)
    except Exception as e:
        return _FileScanResult(path_str, None, f"{path}: {e}", None)


def scan_path(
    root: Path,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
    threads: Optional[int] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    on_finding: Optional[Callable[[Finding], None]] = None,
    on_progress: Optional[Callable[[int, int], None]] = None,
) -> ScanResult:
    """Scan all files under root using a thread pool.

    Args:
        threads: worker thread count (default: os.cpu_count()).
        max_file_size: files larger than this are skipped with a warning.
        chunk_size: bytes read per chunk for memory-efficient scanning.
        on_finding: called for each Finding as soon as its file finishes,
            allowing results to stream to the caller before the whole
            scan completes.
        on_progress: called as (files_completed, files_total) after each
            file finishes, for progress bars.
    """
    result = ScanResult()
    patterns = load_ignore_patterns(root)
    eff_threshold = entropy_threshold if not no_entropy else 999.0

    to_scan: list[Path] = []
    for path in _walk(root):
        if is_ignored(path, root, patterns):
            result.files_skipped += 1
            try:
                result.ignored_files.append(str(path.relative_to(root)))
            except ValueError:
                result.ignored_files.append(str(path))
            continue
        to_scan.append(path)

    worker_threads = threads if threads and threads > 0 else (os.cpu_count() or 4)
    lock = threading.Lock()
    start_time = time.monotonic()

    with ThreadPoolExecutor(max_workers=worker_threads) as executor:
        futures = {
            executor.submit(_scan_file_worker, (p, eff_threshold, max_file_size, chunk_size)): p
            for p in to_scan
        }
        completed = 0
        for future in as_completed(futures):
            file_result = future.result()
            completed += 1

            if file_result.skip_reason == "large":
                with lock:
                    result.files_skipped += 1
                    result.large_files_skipped.append(file_result.path)
            elif file_result.skip_reason == "binary":
                with lock:
                    result.files_skipped += 1
                    result.binary_files_skipped += 1
            elif file_result.error:
                with lock:
                    result.errors.append(file_result.error)
                    result.files_skipped += 1
            else:
                with lock:
                    result.findings.extend(file_result.findings)
                    result.files_scanned += 1
                if on_finding:
                    for f in file_result.findings:
                        on_finding(f)

            if on_progress:
                on_progress(completed, len(to_scan))

    result.elapsed_seconds = time.monotonic() - start_time
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


def scan_staged(
    root: Path,
    entropy_threshold: float = 4.5,
    no_entropy: bool = False,
) -> ScanResult:
    """Scan only git staged (cached) changes. Ideal for pre-commit hooks."""
    result = ScanResult()
    eff_threshold = entropy_threshold if not no_entropy else 999.0

    cmd = ["git", "-C", str(root), "diff", "--cached", "--unified=0"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            result.errors.append("Failed to read staged diff. Is this a git repository?")
            return result
    except FileNotFoundError:
        result.errors.append("git not found in PATH")
        return result
    except Exception as e:
        result.errors.append(str(e))
        return result

    patch = proc.stdout
    if not patch.strip():
        return result

    seen: set[tuple] = set()
    files_touched: set[str] = set()

    for filepath, line_number, line_content in _iter_diff_additions(patch):
        files_touched.add(filepath)
        for f in _check_line(line_content, line_number, filepath, eff_threshold):
            key = (f.matched_value, f.secret_type)
            if key not in seen:
                seen.add(key)
                f.source = "staged"
                result.findings.append(f)

    result.files_scanned = len(files_touched)
    return result


def _walk(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for path in root.rglob("*"):
        if path.is_file():
            yield path
