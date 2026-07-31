"""
Network Security — deterministic rule engine.

Assesses the ACTUAL network indicators in the payload:
- Extracts IP:port pairs and raw ports
- Rates exposed services against a known-risk port table
- Generates concrete firewall hardening rules for the risky exposure found
"""
import re
from typing import Any, Dict, List

# Known-risk service ports: (port, service, risk)
_PORT_TABLE = [
    (23, "Telnet", "CRITICAL"),
    (21, "FTP (plaintext)", "HIGH"),
    (22, "SSH", "MEDIUM"),
    (25, "SMTP (plaintext)", "MEDIUM"),
    (110, "POP3 (plaintext)", "MEDIUM"),
    (143, "IMAP (plaintext)", "MEDIUM"),
    (445, "SMB", "HIGH"),
    (135, "MS-RPC", "HIGH"),
    (137, "NetBIOS", "HIGH"),
    (3389, "RDP", "CRITICAL"),
    (5900, "VNC", "CRITICAL"),
    (6379, "Redis", "HIGH"),
    (9200, "Elasticsearch", "HIGH"),
    (27017, "MongoDB", "HIGH"),
    (11211, "Memcached", "MEDIUM"),
    (5432, "PostgreSQL", "MEDIUM"),
    (3306, "MySQL", "MEDIUM"),
    (8080, "HTTP Alt", "LOW"),
    (8000, "HTTP Dev", "LOW"),
    (1433, "MSSQL", "MEDIUM"),
    (53, "DNS", "LOW"),
    (80, "HTTP", "LOW"),
    (443, "HTTPS", "LOW"),
    (2323, "Telnet Alt", "CRITICAL"),
    (44818, "EtherNet/IP", "MEDIUM"),
]

_PORT_MAP = {p: (s, r) for p, s, r in _PORT_TABLE}
_IP_PORT_PAIR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")


def _collect_ports(raw_input: str, iocs: List[Dict[str, Any]]) -> List[int]:
    ports = []
    for m in _IP_PORT_PAIR.finditer(raw_input):
        ports.append(int(m.group(2)))
    for m in re.finditer(r"(?i)\b(?:port|dstport|dport)\s*[=:]\s*(\d{1,5})\b", raw_input):
        ports.append(int(m.group(1)))
    for m in re.finditer(r"\b(?:tcp|udp)/(\d{1,5})\b", raw_input):
        ports.append(int(m.group(1)))
    # IOCs carrying shodan open ports
    for ioc in iocs:
        for p in (ioc.get("enrichment", {}).get("shodan", {}).get("open_ports", [])) or []:
            ports.append(int(p))
    return list(dict.fromkeys(p for p in ports if 1 <= p <= 65535))


def _ip_port_pairs(raw_input: str) -> List[Dict[str, Any]]:
    pairs = []
    for m in _IP_PORT_PAIR.finditer(raw_input):
        ip, port = m.group(1), int(m.group(2))
        if 1 <= port <= 65535:
            pairs.append({"ip": ip, "port": port})
    return pairs[:20]


def analyze_network_security(raw_input: str, iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic network exposure assessment."""
    ports = _collect_ports(raw_input, iocs)
    pairs = _ip_port_pairs(raw_input)

    port_assessments = []
    for port in ports:
        service, risk = _PORT_MAP.get(port, ("Unknown service", "LOW"))
        port_assessments.append({
            "port": port,
            "service": service,
            "risk": risk,
            "protocol": "tcp",
        })

    # Overall risk = highest risk port present
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if port_assessments:
        worst = min(port_assessments, key=lambda a: risk_order.get(a["risk"], 3))["risk"]
    else:
        worst = "LOW"

    # Firewall hardening rules for critical/high exposure (concrete, real syntax)
    hardening = []
    for a in port_assessments:
        if a["risk"] in ("CRITICAL", "HIGH") and a["port"] not in (22, 443):
            hardening.append({
                "rule": f"nft add rule inet filter input tcp dport {a['port']} drop",
                "description": f"Block inbound {a['service']} (port {a['port']}) until exposed service is verified",
                "rollback": f"nft delete rule inet filter input tcp dport {a['port']} drop",
                "port": a["port"],
            })
    if worst == "LOW" and not hardening:
        hardening.append({
            "rule": "nft add rule inet filter input ct state established,related accept",
            "description": "Maintain stateful default-deny posture for the perimeter",
            "rollback": "nft delete rule inet filter input ct state established,related accept",
            "port": None,
        })

    summary = (
        f"Network exposure assessment reviewed {len(ports)} unique port(s) across "
        f"{len(pairs)} IP:port pair(s). "
        + (f"Highest risk service exposed: {worst}." if port_assessments else "No explicit port exposure found in payload.")
    )

    return {
        "overall_exposure_risk": worst,
        "summary": summary,
        "exposed_services": port_assessments,
        "ip_port_pairs": pairs,
        "hardening_rules": hardening[:10],
        "analysis_source": "deterministic_engine",
    }
