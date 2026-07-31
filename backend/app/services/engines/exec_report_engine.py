"""
Executive Reporting — deterministic rule engine.

Aggregates the REAL state into a board-ready executive summary:
actual finding counts, risk posture, compliance score, CVE exposure, IOCs.
"""
from typing import Any, Dict


def _posture_from_counts(summary: Dict[str, int], risk_posture_hint: str = None) -> str:
    if risk_posture_hint:
        return risk_posture_hint
    if summary.get("CRITICAL", 0) > 0:
        return "CRITICAL"
    if summary.get("HIGH", 0) > 0:
        return "HIGH"
    if summary.get("MEDIUM", 0) > 0:
        return "MEDIUM"
    if summary.get("total", 0) > 0:
        return "LOW"
    return "LOW"


def _recommendations(summary: Dict[str, int], compliance_score, cve_count: int) -> list:
    recs = []
    if summary.get("CRITICAL", 0) or summary.get("HIGH", 0):
        recs.append("Remediate critical and high-severity findings within 24-48 hours")
    if cve_count:
        recs.append(f"Apply vendor patches for the {cve_count} confirmed CVE(s) and track residual exposure")
    if compliance_score is not None and compliance_score < 90:
        recs.append("Close compliance control gaps identified in the GRC assessment")
    if summary.get("total", 0) == 0:
        recs.append("Maintain current hardening baseline and continue continuous monitoring")
    recs.append("Enforce multi-factor authentication and least-privilege access")
    recs.append("Retain logs and enable alerting on the indicators identified")
    return recs[:5]


def _immediate_actions(summary: Dict[str, int]) -> list:
    actions = []
    if summary.get("CRITICAL", 0):
        actions.append("Execute emergency containment for critical findings")
    if summary.get("HIGH", 0):
        actions.append("Assign owners to high-severity findings and begin patching")
    actions.append("Confirm no credential/secret exposure requires rotation")
    actions.append("Review detection coverage for the identified indicators")
    return actions[:4]


def _business_impact(summary: Dict[str, int]) -> str:
    total = summary.get("total", 0)
    if total == 0:
        return (
            "No security findings were confirmed in this assessment. Operational and "
            "financial impact is assessed as minimal for the reviewed scope."
        )
    crit = summary.get("CRITICAL", 0)
    high = summary.get("HIGH", 0)
    return (
        f"{crit} critical and {high} high-severity issue(s) were confirmed across {total} total "
        "findings. Unmitigated, these expose production assets to compromise, which can lead to "
        "data loss, service disruption, regulatory fines, and loss of customer trust."
    )


def analyze_exec_report(state: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic executive summary from real state. ExecutiveSummarySchema-shaped dict."""
    summary = state.get("finding_summary") or {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0, "total": 0,
    }
    compliance = state.get("compliance_report") or {}
    compliance_score = compliance.get("overall_score")
    threat = state.get("threat_intel_report") or {}
    cve_count = len([d for d in threat.get("cve_data", []) if d.get("status") == "found"])
    risk_report = state.get("risk_report") or {}

    posture = risk_report.get("posture") or _posture_from_counts(summary)
    pipeline = state.get("pipeline", "N/A")

    narrative = (
        f"The CORE security platform completed pipeline {pipeline} and confirmed "
        f"{summary['total']} total finding(s): {summary['CRITICAL']} critical, "
        f"{summary['HIGH']} high, {summary['MEDIUM']} medium, {summary['LOW']} low. "
        + (f"The GRC assessment scored compliance at {compliance_score}/100. "
           if compliance_score is not None else "")
        + (f"{cve_count} known CVE(s) were confirmed against the scanned assets. "
           if cve_count else "")
        + f"The resulting organizational risk posture is {posture}."
    )

    regulatory = (
        "Depending on the data processed by the affected assets, exposure may include "
        "GDPR (Articles 33/34 breach notification), PCI DSS (if cardholder data is "
        "in scope), and contractual audit obligations."
    )
    if compliance and compliance.get("critical_gaps"):
        regulatory = (
            "Confirmed compliance gaps include: " + "; ".join(compliance["critical_gaps"][:3])
            + ". These create exposure to audit findings and contractual penalties."
        )

    effort = (
        f"Estimated remediation: approximately {max(summary['total'] * 2, 8)} to "
        f"{max(summary['total'] * 6, 40)} engineering hours, delivered over 1-3 sprints."
        if summary["total"] else "No remediation effort currently required."
    )

    return {
        "executive_headline": (
            f"Security Posture Assessment — {posture} risk with {summary['total']} findings requiring review"
            if summary["total"] else "Security Posture Assessment — no confirmed findings"
        ),
        "executive_narrative": narrative,
        "business_impact_summary": _business_impact(summary),
        "key_recommendations": _recommendations(summary, compliance_score, cve_count),
        "immediate_actions_required": _immediate_actions(summary),
        "risk_posture": posture,
        "regulatory_exposure": regulatory,
        "estimated_remediation_effort": effort,
        "analysis_source": "deterministic_engine",
    }
