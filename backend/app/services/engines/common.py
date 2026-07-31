"""
Shared helpers for the deterministic analysis engines.
"""
import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional

# Reserved IP ranges (RFC 1918 + special-use) excluded from public analysis
PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^224\."),
    re.compile(r"^240\."),
]

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.5, "INFORMATIONAL": 0.5}


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


def max_severity(findings: List[Dict[str, Any]]) -> str:
    """Highest severity present in a list of finding dicts."""
    current = "INFORMATIONAL"
    for f in findings:
        sev = f.get("severity", "INFORMATIONAL")
        if severity_rank(sev) < severity_rank(current):
            current = sev
    return current


def weighted_risk_score(findings: List[Dict[str, Any]]) -> float:
    """Aggregate CVSS-like risk contribution from finding severities. 0-10."""
    if not findings:
        return 0.0
    total = sum(SEVERITY_WEIGHT.get(f.get("severity", "INFORMATIONAL").upper(), 0.5) for f in findings)
    return min(10.0, round(total / math.sqrt(max(len(findings), 1)), 2))


def clamp(value: float, low: float = 0.0, high: float = 10.0) -> float:
    return max(low, min(high, value))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 2.0:
        return "LOW"
    return "INFORMATIONAL"


def top_items(items: List[str], limit: int = 5) -> List[str]:
    seen = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return seen[:limit]


def sha256_entropy(value: str) -> float:
    """Shannon entropy of a hex string. Real property, computed from the data."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_ports_from_text(text: str) -> List[int]:
    """Extract port numbers that appear in network-ish context."""
    ports = []
    for m in re.finditer(r"(?i)\b(?:port|dst|sport|dport|:)\s*[:=]?\s*(\d{1,5})\b", text):
        p = int(m.group(1))
        if 1 <= p <= 65535:
            ports.append(p)
    return ports


def count_keyword_hits(text: str, keywords: List[str]) -> int:
    lowered = text.lower()
    return sum(1 for kw in keywords if kw.lower() in lowered)


def join_sentences(parts: List[str]) -> str:
    return " ".join(p for p in parts if p)
