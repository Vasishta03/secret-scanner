from __future__ import annotations

import json
from pathlib import Path

from scanner.engine import Finding, ScanResult


def save(result: ScanResult, path: Path) -> None:
    data = {
        "version": 1,
        "fingerprints": [f.fingerprint() for f in result.findings],
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


def filter_new(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint() not in baseline]
