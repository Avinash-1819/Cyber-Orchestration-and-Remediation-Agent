"""
Risk Scoring — deterministic rule engine.

Computes an objective, reproducible risk score from the ACTUAL state:
- Impact from finding severity distribution
- Likelihood from evidence volume, exploitability, and compliance failures
- 5x5 risk matrix placement and top-risk ranking
"""
from typing import Any, Dict, List

from app.services.engines.common import SEVERITY_WEIGHT, clamp, severity_from_score

_MATRIX = [
    ["VERY LOW", "LOW", "LOW", "MEDIUM", "HIGH"],
    ["LOW", "LOW", "MEDIUM", "HIGH", "HIGH"],
    ["LOW", "MEDIUM", "HIGH", "HIGH", "CRITICAL"],
    ["MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"],
    ["HIGH", "HIGH", "CRITICAL", "CRITICAL", "CRITICAL"],
]


def _impact_from_findings(findings: List[Dict[str, Any]]) -> float:
    if not findings:
        return 0.0
    weighted = sum(SEVERITY_WEIGHT.get(f.get("severity", "INFORMATIONAL").upper(), 0.5) for f in findings)
    max_w = max(SEVERITY_WEIGHT.get(f.get("severity", "INFORMATIONAL").upper(), 0.5) for f in findings)
    # blend peak severity with aggregate weight, normalized to 0-10
    return clamp(0.6 * max_w + 0.4 * min(weighted / 3.0, 10.0))


def _likelihood(state: Dict[str, Any]) -> float:
    findings = state.get("findings", [])
    score = 2.0
    count = len(findings)
    score += min(count / 3.0, 3.0)

    threat = state.get("threat_intel_report") or {}
    if threat.get("exploitability") and any(k in threat.get("exploitability", "").upper() for k in ("HIGH", "PUBLIC")):
        score += 1.5
    if threat.get("cve_data"):
        if any(d.get("cvss_v3_score", 0) and d["cvss_v3_score"] >= 9.0 for d in threat["cve_data"]):
            score += 1.5
        elif any(d.get("cvss_v3_score", 0) and d["cvss_v3_score"] >= 7.0 for d in threat["cve_data"]):
            score += 1.0

    compliance = state.get("compliance_report") or {}
    if compliance.get("overall_score") is not None and compliance["overall_score"] < 60:
        score += 1.0
    elif compliance.get("overall_score") is not None and compliance["overall_score"] < 85:
        score += 0.5

    if state.get("triage_report") and state["triage_report"].get("classification") == "TRUE_POSITIVE":
        score += 1.0

    return clamp(score)


def _matrix_cell(impact: float, likelihood: float) -> Dict[str, Any]:
    li = min(4, max(0, int(likelihood // 2)))
    im = min(4, max(0, int(impact // 2)))
    level = _MATRIX[im][li]
    return {
        "row": im + 1,
        "column": li + 1,
        "level": level,
    }


def _top_risks(findings: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    ranked = sorted(
        findings,
        key=lambda f: SEVERITY_WEIGHT.get(f.get("severity", "INFORMATIONAL").upper(), 0.5),
        reverse=True,
    )
    return [
        {
            "title": f.get("title", ""),
            "category": f.get("category", ""),
            "severity": f.get("severity", ""),
            "score": SEVERITY_WEIGHT.get(f.get("severity", "INFORMATIONAL").upper(), 0.5),
        }
        for f in ranked[:limit]
    ]


def analyze_risk(state: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic quantitative risk assessment from real state."""
    findings = state.get("findings", [])
    impact = _impact_from_findings(findings)
    likelihood = _likelihood(state)
    score = clamp(round((impact + likelihood) / 2, 2))
    posture = severity_from_score(score)
    cell = _matrix_cell(impact, likelihood)

    drivers = []
    if findings:
        by_cat = {}
        for f in findings:
            by_cat[f.get("category", "Other")] = by_cat.get(f.get("category", "Other"), 0) + 1
        top_cat = sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)[0]
        drivers.append(f"{top_cat[1]} finding(s) in '{top_cat[0]}' drive the impact component")
    if likelihood >= 5:
        drivers.append("Elevated likelihood from exploitability signals and evidence volume")

    return {
        "risk_score": score,
        "posture": posture,
        "impact_score": round(impact, 2),
        "likelihood_score": round(likelihood, 2),
        "matrix_cell": cell,
        "risk_drivers": drivers,
        "top_risks": _top_risks(findings),
        "methodology": "Quantitative severity-weighted scoring (impact x likelihood), 0-10 scale, 5x5 matrix",
        "analysis_source": "deterministic_engine",
    }
