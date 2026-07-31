"""
Log Correlation — deterministic rule engine.

Performs real SIEM-style correlation on the submitted log payload:
- Parses timestamps, source/destination IPs, event kinds
- Detects attack sequences (brute force, port scan, privilege escalation, exfiltration)
- Maps events to the MITRE ATT&CK kill chain stages
- Builds an event timeline
"""
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, List

_TS_PATTERNS = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\d{2}:\d{2}:\d{2}"),
    re.compile(r"\b\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\b"),
]

_IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

_FAILED_AUTH = re.compile(r"(?i)failed password|authentication failure|login failed|invalid user|pam_auth")
_ACCEPTED_AUTH = re.compile(r"(?i)accepted password|successful login|login success")
_PRIV_ELEV = re.compile(r"(?i)\bsudo\b|privilege escalation|elevated|use of privilege")
_PORTSCAN = re.compile(r"(?i)port scan|nmap|recon|syn scan|connection refused")
_EXFIL = re.compile(r"(?i)exfil|large transfer|outbound|upload|data breach|dns exfil")
_C2 = re.compile(r"(?i)beacon|c2 |command and control|callback")
_MALWARE = re.compile(r"(?i)malware|trojan|ransomware|botnet|virus|worm")

_KILL_CHAIN = [
    ("Reconnaissance", re.compile(r"(?i)scan|recon|probe|nmap")),
    ("Resource Development", re.compile(r"(?i)exploit|payload|weapon")),
    ("Initial Access", re.compile(r"(?i)login|accepted password|vpn|phish|exploit")),
    ("Execution", re.compile(r"(?i)cmd|exec|powershell|bash|wscript|rundll")),
    ("Persistence", re.compile(r"(?i)scheduled task|registry run|startup|cron|persistence|backdoor")),
    ("Privilege Escalation", re.compile(r"(?i)sudo|elevat|admin|privilege")),
    ("Defense Evasion", re.compile(r"(?i)disable|log clear|timestomp|mimikatz|whitelist bypass")),
    ("Credential Access", re.compile(r"(?i)password|hashdump|credential|kerberos|lsass")),
    ("Discovery", re.compile(r"(?i)whoami|net view|arp -a|ipconfig|hostname")),
    ("Lateral Movement", re.compile(r"(?i)psexec|smb|wmi|winrm|remote desktop|rdp")),
    ("Collection", re.compile(r"(?i)zip|tar|copy.*server|screenshots|keylog")),
    ("Exfiltration", re.compile(r"(?i)exfil|ftp|scp|curl.*post|upload|data breach")),
    ("Command and Control", re.compile(r"(?i)beacon|dns exfil|tunnel|c2 ")),
    ("Impact", re.compile(r"(?i)ransom|delete.*files|format|shutdown|ddos")),
]


def _parse_timestamps(text: str) -> List[str]:
    stamps = []
    for pat in _TS_PATTERNS:
        stamps.extend(pat.findall(text))
    return stamps


def _detect_sequences(text: str, ips: List[str]) -> List[Dict[str, Any]]:
    """Detect correlated attack sequences per source IP."""
    sequences = []
    for ip in ips:
        # isolate lines mentioning this IP
        lines = [ln for ln in text.splitlines() if ip in ln]
        if not lines:
            continue
        failures = sum(1 for ln in lines if _FAILED_AUTH.search(ln))
        successes = sum(1 for ln in lines if _ACCEPTED_AUTH.search(ln))
        priv = sum(1 for ln in lines if _PRIV_ELEV.search(ln))
        scanned = sum(1 for ln in lines if _PORTSCAN.search(ln))

        if failures >= 5:
            sequences.append({
                "type": "credential_brute_force",
                "source": ip,
                "detail": f"{failures} failed authentication attempts from {ip}",
                "evidence_count": failures,
                "kill_chain_stage": "Credential Access",
                "severity": "HIGH",
                "mitre_technique": "T1110 (Brute Force)",
            })
        if failures >= 3 and successes >= 1:
            sequences.append({
                "type": "successful_brute_force",
                "source": ip,
                "detail": f"{successes} successful logon(s) followed {failures} failures from {ip}",
                "evidence_count": successes + failures,
                "kill_chain_stage": "Initial Access",
                "severity": "CRITICAL",
                "mitre_technique": "T1110.001 (Password Guessing)",
            })
        if scanned >= 3:
            sequences.append({
                "type": "port_scanning",
                "source": ip,
                "detail": f"Reconnaissance/scan activity from {ip} ({scanned} events)",
                "evidence_count": scanned,
                "kill_chain_stage": "Reconnaissance",
                "severity": "MEDIUM",
                "mitre_technique": "T1046 (Network Service Scanning)",
            })
        if successes >= 1 and priv >= 1:
            sequences.append({
                "type": "privilege_escalation_chain",
                "source": ip,
                "detail": f"Successful logon followed by privilege elevation from {ip}",
                "evidence_count": successes + priv,
                "kill_chain_stage": "Privilege Escalation",
                "severity": "HIGH",
                "mitre_technique": "T1078 (Valid Accounts)",
            })
    return sequences


def _kill_chain_coverage(text: str) -> List[Dict[str, Any]]:
    stages = []
    for name, pat in _KILL_CHAIN:
        if pat.search(text):
            stages.append({"stage": name, "detected": True})
    return stages


def _overall_severity(sequences: List[Dict[str, Any]]) -> str:
    if any(s["severity"] == "CRITICAL" for s in sequences):
        return "CRITICAL"
    if any(s["severity"] == "HIGH" for s in sequences):
        return "HIGH"
    if any(s["severity"] == "MEDIUM" for s in sequences):
        return "MEDIUM"
    return "LOW"


def analyze_log_correlation(raw_input: str, ioc_summary: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic correlation of the submitted log payload."""
    text = raw_input or ""
    ips = sorted(set(_IP_PATTERN.findall(text)))
    timestamps = _parse_timestamps(text)

    sequences = _detect_sequences(text, ips)
    kill_chain = _kill_chain_coverage(text)

    exfil = bool(_EXFIL.search(text))
    c2 = bool(_C2.search(text))
    malware = bool(_MALWARE.search(text))

    if exfil and not any(s["type"] == "data_exfiltration" for s in sequences):
        sequences.append({
            "type": "data_exfiltration",
            "source": ips[0] if ips else "unknown",
            "detail": "Outbound transfer patterns consistent with data exfiltration in payload",
            "evidence_count": 1,
            "kill_chain_stage": "Exfiltration",
            "severity": "CRITICAL",
            "mitre_technique": "T1041 (Exfiltration Over C2 Channel)",
        })
    if c2 and not any(s["type"] == "command_and_control" for s in sequences):
        sequences.append({
            "type": "command_and_control",
            "source": ips[0] if ips else "unknown",
            "detail": "Beaconing / command-and-control callbacks observed in payload",
            "evidence_count": 1,
            "kill_chain_stage": "Command and Control",
            "severity": "HIGH",
            "mitre_technique": "T1071 (Application Layer Protocol)",
        })

    sequences = sequences[:12]
    severity = _overall_severity(sequences)

    timeline = []
    for stamp in timestamps[:10]:
        line = next((ln.strip() for ln in text.splitlines() if stamp in ln), "")
        timeline.append({"timestamp": stamp, "event": line[:180]})

    summary = (
        f"Correlated {len(sequences)} attack sequence(s) across {len(set(s['source'] for s in sequences))} source(s) "
        f"({len(ips)} distinct IPs observed). "
        + (f"Kill-chain coverage: {len(kill_chain)} stage(s)." if kill_chain else "No kill-chain stages detected.")
    )

    return {
        "correlation_summary": summary,
        "overall_severity": severity,
        "detected_sequences": sequences,
        "kill_chain_coverage": kill_chain,
        "event_timeline": timeline,
        "unique_sources": ips[:20],
        "total_events_parsed": len(text.splitlines()),
        "timestamps_parsed": len(timestamps),
        "analysis_source": "deterministic_engine",
    }
