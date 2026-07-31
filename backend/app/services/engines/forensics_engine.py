"""
Forensics — deterministic rule engine.

Performs real digital-forensics-oriented analysis on the submitted artifacts:
- Hash algorithm identification (length-based) + entropy
- Event timeline reconstruction from timestamps
- Artifact classification (log types, hashes, network indicators)
- Chain-of-custody record
"""
import re
from typing import Any, Dict, List

from app.services.engines.common import sha256_entropy

_TS_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\b\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\b"),
]

_HASH_PATTERNS = [
    (32, "MD5"),
    (40, "SHA-1"),
    (56, "SHA-224"),
    (64, "SHA-256"),
    (96, "SHA-384"),
    (128, "SHA-512"),
]

_LOG_TYPES = [
    ("SSH / auth", re.compile(r"(?i)sshd|failed password|accepted password|auth\.log")),
    ("Firewall / IDS", re.compile(r"(?i)iptables|firewall|ids|ips|suricata|snort|pf:")),
    ("Web server", re.compile(r"(?i)nginx|apache|iis|GET /|POST /")),
    ("Windows Event", re.compile(r"(?i)event id|eventlog|windows security|security log")),
    ("Network flow", re.compile(r"(?i)netflow|conversation|flow record")),
]

_HASH_HEX = re.compile(r"\b[a-fA-F0-9]{32,}\b")


def _classify_artifacts(text: str, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    artifacts = []
    detected_types = [name for name, pat in _LOG_TYPES if pat.search(text)]
    for name in detected_types:
        artifacts.append({"kind": "log_type", "name": name, "evidence": f"Payload matches {name} log characteristics"})

    for ioc in iocs:
        kind = ioc.get("type")
        value = ioc.get("value", "")
        if kind == "Hash":
            algo = "unknown"
            for length, name in _HASH_PATTERNS:
                if len(value) == length:
                    algo = name
                    break
            artifacts.append({
                "kind": "file_hash",
                "name": f"{algo} digest",
                "evidence": f"SHA256 entropy {round(sha256_entropy(value), 2)} bits; {len(value)} hex chars",
            })
        elif kind == "IP":
            artifacts.append({"kind": "network_indicator", "name": "IPv4 address", "evidence": value})
        elif kind == "Domain":
            artifacts.append({"kind": "network_indicator", "name": "Domain", "evidence": value})

    if not artifacts:
        artifacts.append({"kind": "raw_payload", "name": "unstructured evidence", "evidence": "No distinct artifact signatures matched"})
    return artifacts[:20]


def _reconstruct_timeline(text: str) -> List[Dict[str, Any]]:
    timeline = []
    for pat in _TS_PATTERNS:
        for stamp in pat.findall(text):
            line = next((ln.strip() for ln in text.splitlines() if stamp in ln), "")
            timeline.append({"timestamp": stamp, "event": line[:200]})
            if len(timeline) >= 25:
                break
        if len(timeline) >= 25:
            break
    return timeline


def analyze_forensics(raw_input: str, ioc_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic forensic triage of the submitted artifacts."""
    text = raw_input or ""
    artifacts = _classify_artifacts(text, ioc_summary)
    timeline = _reconstruct_timeline(text)

    hashes = [a for a in artifacts if a["kind"] == "file_hash"]
    network_indicators = [a for a in artifacts if a["kind"] == "network_indicator"]

    integrity_notes = []
    if hashes:
        integrity_notes.append(
            f"{len(hashes)} file hash(es) recorded as acquisition evidence; hashes enable "
            "baselining and malware-signature matching."
        )
    if timeline:
        integrity_notes.append(f"Event timeline reconstructed from {len(timeline)} timestamped entries.")
    if network_indicators:
        integrity_notes.append(f"{len(network_indicators)} network indicator(s) captured for correlation.")
    if not integrity_notes:
        integrity_notes.append("No timestamped or hashed artifacts were present — timeline reconstruction limited.")

    return {
        "acquisition_summary": (
            f"Forensic triage identified {len(artifacts)} distinct artifact(s) and "
            f"reconstructed a {len(timeline)}-entry event timeline."
        ),
        "artifacts": artifacts,
        "event_timeline": timeline,
        "chain_of_custody": [
            "Collected via user-submitted evidence payload",
            f"Timestamps captured: {len(timeline)} entries",
            "Evidence preserved in-session and exportable via report artifacts",
        ],
        "integrity_notes": integrity_notes,
        "recommended_next_steps": [
            "Acquire full disk/memory images from affected hosts",
            "Validate hashes against public threat-intel repositories",
            "Correlate network indicators with perimeter and DNS logs",
        ],
        "analysis_source": "deterministic_engine",
    }
