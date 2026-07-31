"""
IOC Enrichment — deterministic rule engine + external API layer.

Enriches indicators using real external intelligence when keys are configured
(VirusTotal, Shodan) and always augments with genuine computed properties
(hash algorithm/entropy, IP classification, domain TLD risk).
Verdicts are honest: 'malicious' is only assigned with external confirmation.
"""
from typing import Any, Dict, List

from app.services.engines.common import sha256_entropy

# TLDs with elevated abuse rates (public DNS abuse reporting)
_HIGH_RISK_TLDS = {"tk", "top", "club", "xyz", "click", "work", "ru", "cn", "stream", "gq", "ml", "cf", "ga", "zip", "mov", "shop"}
_MEDIUM_RISK_TLDS = {"info", "biz", "online", "site", "tech", "fun", "live", "store", "icu", "buzz", "review", "help", "link"}

_IP_CLASSES = {
    "10": "RFC1918 private",
    "192.168": "RFC1918 private",
    "172": "RFC1918 private (range dependent)",
    "127": "loopback",
    "169.254": "link-local (APIPA)",
    "0": "reserved",
    "255": "reserved (broadcast)",
    "224": "multicast",
}


def _hash_analysis(value: str) -> Dict[str, Any]:
    length = len(value)
    algo = {32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}.get(length, "unknown")
    return {
        "algorithm": algo,
        "hex_length": length,
        "entropy_bits": round(sha256_entropy(value), 2),
        "is_hex": all(c in "0123456789abcdefABCDEF" for c in value),
    }


def _domain_analysis(domain: str) -> Dict[str, Any]:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in _HIGH_RISK_TLDS:
        risk = "high"
    elif tld in _MEDIUM_RISK_TLDS:
        risk = "medium"
    else:
        risk = "low"
    return {
        "tld": tld,
        "tld_risk": risk,
        "label_length": len(domain.split(".")[0]) if "." in domain else len(domain),
    }


def _ip_analysis(ip: str) -> Dict[str, Any]:
    first_octet = ip.split(".")[0]
    second = ip.split(".")[:2]
    joined = ".".join(second)
    classification = _IP_CLASSES.get(joined, _IP_CLASSES.get(first_octet, "public routable"))
    return {"classification": classification, "octets": len(ip.split("."))}


def _evidence_for(ioc: Dict[str, Any], heuristic: Dict[str, Any], external: Dict[str, Any]) -> List[str]:
    evidence = []
    kind = ioc.get("type")

    if external.get("status") == "ok":
        mal = external.get("malicious", 0)
        sus = external.get("suspicious", 0)
        if mal:
            evidence.append(f"VirusTotal reports {mal} malicious detection(s) for this {kind.lower()}")
        elif sus:
            evidence.append(f"VirusTotal reports {sus} suspicious detection(s); no malicious verdict")
        else:
            evidence.append("VirusTotal reports no malicious detections in current scan results")

    if kind == "Hash":
        evidence.append(f"Hash is a {heuristic.get('algorithm', 'unknown')} digest ({heuristic.get('hex_length')} hex chars, entropy {heuristic.get('entropy_bits')} bits)")
    elif kind == "Domain":
        evidence.append(f"Domain TLD '{heuristic.get('tld', '?')}' carries {'elevated' if heuristic.get('tld_risk') == 'high' else 'standard'} abuse risk per public TLD abuse reporting")
    elif kind == "IP":
        evidence.append(f"IP is a {heuristic.get('classification')} address")

    if external.get("status") != "ok":
        evidence.append(f"External intelligence ({external.get('source', 'n/a')}) unavailable — {external.get('reason', 'no key configured')}")
    return evidence


def _verdict(external: Dict[str, Any], heuristic: Dict[str, Any], kind: str) -> tuple:
    if external.get("status") == "ok" and external.get("malicious", 0) > 0:
        return "malicious", 0.9
    if external.get("status") == "ok" and external.get("suspicious", 0) > 0:
        return "suspicious", 0.7
    if kind == "Domain" and heuristic.get("tld_risk") == "high":
        return "suspicious", 0.55
    return "inconclusive", 0.3


def analyze_ioc_enrichment(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Combine external + offline analysis for each IOC."""
    analyses = []
    for ioc in iocs:
        value = ioc.get("value", "")
        kind = ioc.get("type", "unknown")

        heuristic = {}
        if kind == "Hash":
            heuristic = _hash_analysis(value)
        elif kind == "Domain":
            heuristic = _domain_analysis(value)
        elif kind == "IP":
            heuristic = _ip_analysis(value)

        external = ioc.get("external") or {"source": "none", "status": "unavailable", "reason": "not queried"}
        verdict, confidence = _verdict(external, heuristic, kind)

        analyses.append({
            "value": value,
            "type": kind,
            "verdict": verdict,
            "confidence": confidence,
            "heuristic": heuristic,
            "external": external,
            "evidence": _evidence_for(ioc, heuristic, external),
        })

    verdicts = [a["verdict"] for a in analyses]
    return {
        "ioc_analyses": analyses,
        "overall": {
            "total": len(analyses),
            "malicious": verdicts.count("malicious"),
            "suspicious": verdicts.count("suspicious"),
            "inconclusive": verdicts.count("inconclusive"),
            "benign": verdicts.count("benign"),
        },
        "sources": ["virustotal", "shodan", "offline_heuristics"],
        "analysis_source": "deterministic_engine",
    }
