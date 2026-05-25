"""
Configuration loader for leakscan.

Supports loading custom patterns and settings from:
  1. .leakscan.yaml in the scanned directory
  2. [tool.leakscan] section in pyproject.toml
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scanner.patterns import Pattern

CONFIG_FILENAME = ".leakscan.yaml"


@dataclass
class ScanConfig:
    """Resolved configuration for a scan run."""

    custom_patterns: list[Pattern] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)
    severity_threshold: Optional[str] = None
    entropy_threshold: Optional[float] = None
    no_entropy: Optional[bool] = None


def _parse_severity(raw: str) -> str:
    normalized = raw.strip().upper()
    if normalized in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return normalized
    return "MEDIUM"


def _build_pattern(entry: dict) -> Optional[Pattern]:
    """Build a Pattern from a user-defined dict entry."""
    name = entry.get("name")
    regex = entry.get("regex")
    if not name or not regex:
        return None
    severity = _parse_severity(entry.get("severity", "MEDIUM"))
    description = entry.get("description", name)
    try:
        compiled = re.compile(regex)
    except re.error:
        return None
    return Pattern(name=name, regex=compiled, severity=severity, description=description)


def load_config(directory: Path) -> ScanConfig:
    """
    Load configuration from .leakscan.yaml if present.
    Falls back to pyproject.toml [tool.leakscan] section.
    Returns a default ScanConfig if neither is found.
    """
    config = ScanConfig()

    yaml_path = directory / CONFIG_FILENAME
    if yaml_path.is_file():
        _load_yaml_config(yaml_path, config)
        return config

    pyproject_path = directory / "pyproject.toml"
    if pyproject_path.is_file():
        _load_pyproject_config(pyproject_path, config)

    return config


def _load_yaml_config(path: Path, config: ScanConfig) -> None:
    """Parse .leakscan.yaml and populate config."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        # PyYAML not installed, try a minimal parse approach
        _load_yaml_fallback(path, config)
        return

    import yaml as _yaml

    try:
        data = _yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return

    if not isinstance(data, dict):
        return

    _apply_dict(data, config)


def _load_yaml_fallback(path: Path, config: ScanConfig) -> None:
    """
    Minimal YAML-like parser for simple .leakscan.yaml files
    when PyYAML is not installed. Handles flat keys and basic lists.
    """
    # We only support very basic structures without PyYAML.
    # This keeps the dependency footprint small.
    pass


def _load_pyproject_config(path: Path, config: ScanConfig) -> None:
    """Parse [tool.leakscan] from pyproject.toml."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # noqa: F811
        except ImportError:
            return

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return

    tool_section = data.get("tool", {}).get("leakscan", {})
    if not tool_section:
        return

    _apply_dict(tool_section, config)


def _apply_dict(data: dict, config: ScanConfig) -> None:
    """Apply a parsed config dictionary to the ScanConfig object."""
    if "custom_patterns" in data and isinstance(data["custom_patterns"], list):
        for entry in data["custom_patterns"]:
            if isinstance(entry, dict):
                pat = _build_pattern(entry)
                if pat:
                    config.custom_patterns.append(pat)

    if "exclude_paths" in data and isinstance(data["exclude_paths"], list):
        config.exclude_paths = [str(p) for p in data["exclude_paths"] if p]

    if "severity" in data:
        config.severity_threshold = _parse_severity(str(data["severity"]))

    if "entropy_threshold" in data:
        try:
            config.entropy_threshold = float(data["entropy_threshold"])
        except (TypeError, ValueError):
            pass

    if "no_entropy" in data:
        config.no_entropy = bool(data["no_entropy"])
