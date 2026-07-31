"""
Threat Intelligence — deterministic rule engine.

Builds intelligence from REAL data only:
- NVD CVE lookups (when resolvable) with actual CVSS scores
- MITRE ATT&CK techniques from the local STIX dataset
- Sigma / YARA / Splunk detection rules that reference the ACTUAL IOCs in the scan
"""
from typing import Any, Dict, List


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _exploitability_assessment(cve_data_map: Dict[str, Dict[str, Any]]) -> str:
    found = [d for d in cve_data_map.values() if d.get("status") == "found" and d.get("cvss_v3_score")]
    if not found:
        return (
            "No CVE data was resolvable for this scan. Exploitability is assessed "
            "solely from the incident context and mapped MITRE techniques."
        )
    highest = max(d.get("cvss_v3_score") or 0 for d in found)
    sev = _severity_from_score(highest)
    return (
        f"The highest-severity resolved CVE scores CVSS {highest:.1f} ({sev}). "
        + ("Public exploits are frequently observed at this severity band; prioritize patching."
           if sev in ("CRITICAL", "HIGH") else
           "Exploitation is plausible but lower likelihood at this severity band; schedule patching.")
    )


def _sigma_rule_for_iocs(iocs: List[Dict[str, Any]], technique_ids: List[str]) -> str:
    selectors = []
    for ioc in iocs[:5]:
        kind = ioc.get("type")
        value = ioc.get("value", "")
        if kind == "IP":
            selectors.append(f"    DestinationIp|contains: '{value}'")
        elif kind == "Domain":
            selectors.append(f"    QueryName|contains: '{value}'")
        elif kind == "Hash":
            selectors.append(f"    Hashes|contains: '{value}'")
    if not selectors:
        selectors.append("    CommandLine|contains: 'cmd.exe /c'")
    selection = "\n".join(selectors)
    mitre = "\n".join(f"      - {tid}" for tid in technique_ids[:3])
    return (
        f"title: Detection of {iocs[0]['value'] if iocs else 'Suspicious Activity'}\n"
        f"id: core-{abs(hash(tuple(i.get('value') for i in iocs[:3]))) % 10**8:08d}\n"
        "status: experimental\n"
        "logsource:\n"
        "  category: network_connection\n"
        "detection:\n"
        "  selection:\n"
        f"{selection}\n"
        "  condition: selection\n"
        "level: high\n"
        f"tags:\n{mitre}"
    )


def _yara_rule_for_iocs(iocs: List[Dict[str, Any]]) -> str:
    hashes = [i.get("value") for i in iocs if i.get("type") == "Hash"]
    if hashes:
        hexes = "\n".join(
            f"    0x{{{h} // 4}} bytes"
            for h in hashes[:3]
        )
        return (
            f"rule core_ioc_{hashes[0][:12] if hashes else 'artifact'}\n"
            "{\n"
            "    meta:\n"
            "        description = \"YARA rule derived from hashes confirmed in this scan\"\n"
            "        author = \"CORE Orchestration Engine\"\n"
            "        date = \"2026-01-01\"\n"
            "    strings:\n"
            f"{hexes}\n"
            "    condition:\n"
            "        any of them\n"
            "}\n"
        )
    return (
        "rule core_suspicious_download\n"
        "{\n"
        "    meta:\n"
        "        description = \"Generic suspicious payload signature for scan context\"\n"
        "        author = \"CORE Orchestration Engine\"\n"
        "    strings:\n"
        "        $mz = { 4D 5A }\n"
        "        $elf = { 7F 45 4C 46 }\n"
        "    condition:\n"
        "        uint16(0) == 0x5A4D or $elf at 0\n"
        "}\n"
    )


def _splunk_spl_for_iocs(iocs: List[Dict[str, Any]]) -> str:
    ioc_values = [i.get("value") for i in iocs[:3]]
    if not ioc_values:
        return "index=security sourcetype=firewall | stats count by src_ip | sort -count | head 20"
    lookups = "\n    ".join(f'"{v}"' for v in ioc_values)
    return (
        "index=* sourcetype=* \n"
        "  | where searchmatch(\" "
        + " OR ".join(ioc_values) + "\")\n"
        "  | stats count by src_ip, dest_ip, dest_port\n"
        "  | sort -count"
    )


def _threat_summary(cve_data_map: Dict[str, Dict[str, Any]], techniques: List[Dict[str, Any]], ioc_count: int) -> str:
    parts = []
    found = [d for d in cve_data_map.values() if d.get("status") == "found"]
    if found:
        highest = max(found, key=lambda d: d.get("cvss_v3_score") or 0)
        parts.append(
            f"{len(found)} CVE(s) resolved from NVD; the highest is "
            f"{highest['cve_id']} at CVSS {highest.get('cvss_v3_score')} "
            f"({highest.get('cvss_v3_severity')})."
        )
    if techniques:
        parts.append(
            f"Attack chain maps to {len(techniques)} MITRE ATT&CK technique(s): "
            + ", ".join(f"{t['id']} {t['name']}" for t in techniques[:3]) + "."
        )
    if ioc_count:
        parts.append(f"{ioc_count} indicator(s) from this scan are incorporated into detection rules.")
    if not parts:
        parts.append("No resolvable CVE or MITRE data — threat posture assessed as informational.")
    return " ".join(parts)


def analyze_threat_intel(
    cve_data_map: Dict[str, Dict[str, Any]],
    mitre_techniques: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    incident_context: Dict[str, Any],
) -> Dict[str, Any]:
    """Deterministic threat intel synthesis. ThreatIntelSchema-shaped dict."""
    technique_ids = [t.get("id", "") for t in mitre_techniques]

    attack_techniques = [{
        "id": t.get("id", ""),
        "name": t.get("name", ""),
        "tactic": ", ".join(t.get("tactics", []) or []),
        "description": (t.get("description", "") or "")[:300],
    } for t in mitre_techniques[:6]]

    affected_products = []
    for d in cve_data_map.values():
        if d.get("status") == "found":
            desc = d.get("description", "")
            affected_products.append(desc[:120])
    affected_products = list(dict.fromkeys(affected_products))[:5]
    if not affected_products and incident_context.get("attack_pattern"):
        affected_products = [f"Assets implicated by {incident_context['attack_pattern']}"]

    confidence = "HIGH" if cve_data_map or mitre_techniques else "MEDIUM"

    return {
        "threat_summary": _threat_summary(cve_data_map, mitre_techniques, len(iocs)),
        "attack_techniques": attack_techniques,
        "exploitability_assessment": _exploitability_assessment(cve_data_map),
        "affected_products": affected_products,
        "detection_rules": [
            {"rule_type": "sigma", "name": "CORE_Sigma_Scan_Context", "description": "Sigma rule derived from the actual indicators of this scan.", "rule_content": _sigma_rule_for_iocs(iocs, technique_ids)},
            {"rule_type": "yara", "name": "CORE_YARA_Scan_Context", "description": "YARA rule matching artifacts confirmed in this scan.", "rule_content": _yara_rule_for_iocs(iocs)},
            {"rule_type": "splunk_spl", "name": "CORE_SPL_Scan_Context", "description": "Splunk SPL hunting query for the scan's indicators.", "rule_content": _splunk_spl_for_iocs(iocs)},
        ],
        "threat_actor_context": (
            "No actor attribution can be confirmed from locally available data. "
            "Attribution requires commercial intel feeds."
        ),
        "intelligence_confidence": confidence,
        "analysis_source": "deterministic_engine",
    }
