"""
Incident Triage — deterministic rule engine.

Performs real evidence-based triage on raw log/event payloads:
- Severity signal scoring from actual content
- IOC extraction context
- True/False positive determination from evidence
- Immediate actions derived from the actual IOCs present
"""
import re
from collections import Counter
from typing import Any, Dict, List

from app.services.engines.common import top_items

# Signal keyword groups weighted by severity. Only count when actually present in input.
_SEVERITY_SIGNALS: Dict[str, List[str]] = {
    "CRITICAL": [
        "ransomware", "credential dump", "exfiltration", "backdoor", "privilege escalation",
        "lateral movement", "root access", "mass compromise", "data breach", "c2 server",
        "command and control", "encrypting", "golden ticket", "zero-day", "zeroday",
        "bootkit", "rookit", "rootkit", "domain admin compromised",
    ],
    "HIGH": [
        "malware", "intrusion", "exploit", "phishing", "unauthorized", "persistence",
        "brute force", "bruteforce", "password spray", "sudo", "shell access", "webshell",
        "reverse shell", "meterpreter", "cobalt strike", "mimikatz", "keylogger",
        "sql injection", "xss", "traversal", "ssrf", "rce", "remote code execution",
    ],
    "MEDIUM": [
        "failed password", "authentication failure", "login failed", "403", "404",
        "port scan", "nmap", "suspicious", "anomalous", "policy violation", "spam",
        "dos", "ddos", "tampering", "misconfig", "misconfiguration",
    ],
    "LOW": [
        "warning", "notice", "retry", "timeout", "slow", "error",
    ],
}

# Attack pattern inference: first matching signal wins
_PATTERN_RULES: List[Dict[str, Any]] = [
    {"keywords": ["ransomware", "encrypting", "locker", "crypto"], "pattern": "Ransomware Deployment"},
    {"keywords": ["credential dump", "mimikatz", "password spray", "brute force", "bruteforce", "failed password"], "pattern": "Credential Brute-Force / Credential Theft"},
    {"keywords": ["phishing", "spearphishing", "spam"], "pattern": "Phishing Campaign"},
    {"keywords": ["exfiltration", "data breach", "outbound", "upload"], "pattern": "Data Exfiltration"},
    {"keywords": ["backdoor", "webshell", "reverse shell", "persistence"], "pattern": "Backdoor / Persistence Establishment"},
    {"keywords": ["exploit", "rce", "remote code execution", "zero-day", "zeroday", "cve-"], "pattern": "Exploit of Known Vulnerability"},
    {"keywords": ["port scan", "nmap", "recon", "probe"], "pattern": "Network Reconnaissance / Scanning"},
    {"keywords": ["malware", "trojan", "botnet"], "pattern": "Malware Infection"},
    {"keywords": ["sql injection", "xss", "traversal", "ssrf", "command injection"], "pattern": "Web Application Attack"},
    {"keywords": ["dos", "ddos", "flood"], "pattern": "Denial of Service"},
]

_CRITICAL_ACTIONS = [
    "Isolate affected assets from the network immediately",
    "Suspend compromised accounts and rotate credentials",
    "Preserve volatile evidence (memory, network connections) before shutdown",
    "Engage incident response team and notify stakeholders",
]

_HIGH_ACTIONS = [
    "Block confirmed malicious IOCs at the perimeter firewall",
    "Terminate malicious sessions and quarantine endpoints",
    "Review authentication logs for further compromised accounts",
    "Rotate credentials used by affected systems",
]

_MEDIUM_ACTIONS = [
    "Correlate events across sources for surrounding activity",
    "Tune detection rules to reduce noise and capture related activity",
    "Restrict network access from scanning sources",
]

_LOW_ACTIONS = [
    "Retain logs and monitor for recurring activity",
]


def _signal_severity(text: str) -> str:
    lowered = text.lower()
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        for kw in _SEVERITY_SIGNALS[sev]:
            if kw in lowered:
                return sev
    if any(kw in lowered for kw in _SEVERITY_SIGNALS["LOW"]):
        return "LOW"
    return "INFORMATIONAL"


def _detect_pattern(text: str) -> str:
    lowered = text.lower()
    for rule in _PATTERN_RULES:
        if any(kw in lowered for kw in rule["keywords"]):
            return rule["pattern"]
    return "Potential Security Anomaly"


def _evidence_points(text: str, severity: str) -> List[str]:
    lowered = text.lower()
    evidence = []

    auth_failures = len(re.findall(r"(?i)failed password|authentication failure", text))
    if auth_failures:
        evidence.append(f"{auth_failures} failed authentication attempts recorded in the submitted payload")

    success_logins = len(re.findall(r"(?i)accepted password|successful login", text))
    if success_logins:
        evidence.append(f"{success_logins} successful logon events recorded after the failures")

    sudo_events = len(re.findall(r"(?i)\bsudo\b|privileged command", text))
    if sudo_events:
        evidence.append(f"{sudo_events} privilege-elevation (sudo/privileged) events recorded")

    if any(kw in lowered for kw in ("root", "rootkit", "backdoor", "persistence")):
        evidence.append("Signals of privileged-access compromise or persistence present in payload")

    if severity in ("CRITICAL", "HIGH"):
        for kw in _SEVERITY_SIGNALS[severity]:
            if kw in lowered:
                evidence.append(f"Confirmed security signal keyword present: {kw}")
                break

    if not evidence:
        evidence.append("No high-confidence malicious indicators matched in the submitted payload")
    return evidence[:8]


def _affected_assets(text: str) -> List[str]:
    assets = []
    hostname_pat = re.compile(r"(?i)(?:host|hostname|server|asset|machine|client)\s*[=:]?\s*([a-z0-9][a-z0-9\-_.]{2,63})")
    for m in hostname_pat.finditer(text):
        asset = m.group(1)
        if asset not in assets:
            assets.append(asset)
    # Prefer the most frequently mentioned asset-like tokens
    tokens = re.findall(r"\b(?:prod|stg|dev|web|db|app|server)-[a-z0-9\-]+", text, re.IGNORECASE)
    for t in tokens:
        if t.lower() not in [a.lower() for a in assets]:
            assets.append(t.lower())
    return top_items(assets, 6)


def analyze_triage(raw_input: str, ioc_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic triage of the raw payload. Returns TriageAnalysisSchema-shaped dict."""
    text = raw_input or ""
    severity = _signal_severity(text)
    pattern = _detect_pattern(text)
    evidence = _evidence_points(text, severity)

    ioc_count = len(ioc_summary)
    public_ips = [i for i in ioc_summary if i.get("type") == "IP"]

    # TRUE_POSITIVE determination must be evidence-based
    classification = "TRUE_POSITIVE" if severity in ("CRITICAL", "HIGH", "MEDIUM") or ioc_count >= 1 else "FALSE_POSITIVE"
    if severity == "LOW" and ioc_count == 0:
        classification = "FALSE_POSITIVE"

    confidence = 0.95 if severity == "CRITICAL" else (
        0.9 if severity == "HIGH" else (0.8 if severity == "MEDIUM" else 0.75)
    )

    if classification == "TRUE_POSITIVE":
        if public_ips:
            evidence.append(
                f"{len(public_ips)} public-facing IP indicator(s) present in payload"
            )
        if ioc_count > len(public_ips):
            evidence.append(f"{ioc_count - len(public_ips)} non-IP indicator(s) (domains/hashes) extracted")

    actions = _CRITICAL_ACTIONS if severity == "CRITICAL" else (
        _HIGH_ACTIONS if severity == "HIGH" else (
            _MEDIUM_ACTIONS if severity == "MEDIUM" else _LOW_ACTIONS
        )
    )

    # Derive a targeted block action from the actual IPs present
    for ioc in public_ips[:1]:
        ip = ioc.get("value")
        actions = [
            f"Block confirmed indicator {ip} at the perimeter firewall and IDS/IPS",
            *[a for a in actions if "Block confirmed malicious IOCs" not in a],
        ]

    one_liner = (
        f"Confirmed {severity}-priority security event ({pattern.lower()}) requiring immediate attention."
        if classification == "TRUE_POSITIVE"
        else "No high-confidence malicious indicators confirmed — event triaged as likely false positive."
    )

    return {
        "classification": classification,
        "confidence": confidence,
        "severity": severity,
        "attack_pattern": pattern,
        "affected_assets": _affected_assets(text) or ["undetermined-asset"],
        "key_findings": top_items(evidence, 8),
        "recommended_immediate_actions": top_items(actions, 6),
        "executive_one_liner": one_liner,
        "analysis_source": "deterministic_engine",
    }
