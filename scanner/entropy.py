import math
import re
from dataclasses import dataclass

MIN_LENGTH = 20
ENTROPY_THRESHOLD = 4.5

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"

_QUOTED_RE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""")
_UNQUOTED_RE = re.compile(r"""(?:^|[=:\s])([A-Za-z0-9+/=_\-]{20,})(?=\s*(?:#|//|$))""")


def shannon_entropy(data: str, charset: str) -> float:
    filtered = [c for c in data if c in charset]
    if not filtered:
        return 0.0
    length = len(filtered)
    freq = {c: filtered.count(c) / length for c in set(filtered)}
    return -sum(p * math.log2(p) for p in freq.values())


def score(value: str) -> float:
    return max(
        shannon_entropy(value, BASE64_CHARS),
        shannon_entropy(value, HEX_CHARS),
    )


@dataclass
class EntropyFinding:
    value: str
    entropy: float
    line_number: int
    line: str


def scan_line(line: str, line_number: int, threshold: float = ENTROPY_THRESHOLD) -> list[EntropyFinding]:
    findings = []
    seen_values: set[str] = set()

    for pattern in (_QUOTED_RE, _UNQUOTED_RE):
        for match in pattern.finditer(line):
            candidate = match.group(1)
            if not candidate or len(candidate) < MIN_LENGTH or candidate in seen_values:
                continue
            seen_values.add(candidate)
            s = score(candidate)
            if s >= threshold:
                findings.append(EntropyFinding(
                    value=candidate,
                    entropy=round(s, 3),
                    line_number=line_number,
                    line=line.rstrip(),
                ))

    return findings
