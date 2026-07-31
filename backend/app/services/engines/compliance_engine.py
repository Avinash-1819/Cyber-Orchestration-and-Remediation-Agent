"""
Compliance (GRC) — deterministic rule engine.

Evaluates the ACTUAL findings against the versioned control mappings in
data/compliance_mappings/*.yaml. Only real control IDs from those files are
ever reported — nothing is invented. Scoring is a weighted pass/fail rate.
"""
from pathlib import Path
from typing import Any, Dict, List

import yaml

from app.core.config import settings
from app.services.engines.common import severity_rank

FRAMEWORKS = ["ISO27001", "SOC2", "NIST_800_53", "PCI_DSS_4"]
_FRAMEWORK_LABEL = {
    "ISO27001": "ISO 27001",
    "SOC2": "SOC 2",
    "NIST_800_53": "NIST 800-53",
    "PCI_DSS_4": "PCI DSS 4",
}


def _load_mappings() -> Dict[str, Any]:
    """Load versioned control mappings from YAML. Returns {} if unavailable."""
    mapping_dir = Path(settings.COMPLIANCE_MAPPINGS_DIR)
    if not mapping_dir.exists():
        mapping_dir = Path(__file__).resolve().parent.parent.parent.parent / "data" / "compliance_mappings"
    if not mapping_dir.exists():
        return {}

    mappings = {}
    for f in mapping_dir.glob("*.yaml"):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                mappings[f.stem] = yaml.safe_load(fh)
        except Exception:
            continue
    return mappings


def _category_for_finding(finding: Dict[str, Any]) -> str:
    category = finding.get("category", "")
    if category.startswith("Compliance-"):
        return "Compliance"
    if "CVE" in category:
        return "CVE"
    if category in ("Secrets", "Incident", "Remediation", "Dockerfile", "IaC-Misconfiguration"):
        return category
    if category.startswith("OWASP-"):
        return category
    if category.startswith("Cloud"):
        return "IaC-Misconfiguration"
    if category.startswith("Network"):
        return "IaC-Misconfiguration"
    if category.startswith("Risk"):
        return "Compliance"
    return "Incident"


def analyze_compliance(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic compliance assessment. ComplianceAnalysisSchema-shaped dict."""
    mappings = _load_mappings()
    assessments: List[Dict[str, Any]] = []
    critical_gaps: List[str] = []
    evidence_checklist: List[str] = []

    # Index findings by normalized category
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        cat = _category_for_finding(finding)
        by_category.setdefault(cat, []).append(finding)

    for framework_key in FRAMEWORKS:
        framework_data = mappings.get(framework_key, {}).get("mappings", {})
        if not framework_data:
            continue
        label = _FRAMEWORK_LABEL.get(framework_key, framework_key)

        for category, mapping in framework_data.items():
            control_id = mapping.get("control_id")
            control_name = mapping.get("control_name", "Security control")
            matched = by_category.get(category, [])

            if not matched:
                status = "NOT_APPLICABLE"
                rationale = (
                    f"No findings of type '{category}' were present in this assessment, "
                    f"so {control_id} is not evaluated."
                )
                related = []
            else:
                worst = min((f.get("severity", "INFORMATIONAL") for f in matched), key=severity_rank)
                if severity_rank(worst) <= severity_rank("HIGH"):
                    status = "FAILED"
                elif severity_rank(worst) == severity_rank("MEDIUM"):
                    status = "ACTION_REQUIRED"
                else:
                    status = "PASSED"
                related = [f.get("id", "?") for f in matched]
                rationale = (
                    f"Evidence in this scan shows {len(matched)} finding(s) of type "
                    f"'{category}' (worst severity {worst}); control {control_id} "
                    f"is assessed as {status}."
                )
                if status in ("FAILED", "ACTION_REQUIRED"):
                    critical_gaps.append(f"{label} {control_id}: {control_name}")
                    evidence_checklist.append(
                        f"{label} {control_id} — evidence of remediation for: "
                        + "; ".join(f.get("title", "")[:80] for f in matched[:3])
                    )

            assessments.append({
                "control_id": control_id,
                "control_name": control_name,
                "framework": label,
                "status": status,
                "rationale": rationale,
                "related_finding_ids": related,
            })

    # Weighted score: FAILED=0, ACTION_REQUIRED=0.5, PASSED=1, NOT_APPLICABLE excluded
    scored = [a for a in assessments if a["status"] != "NOT_APPLICABLE"]
    if scored:
        weights = {"FAILED": 0.0, "ACTION_REQUIRED": 0.5, "PASSED": 1.0}
        overall_score = round(100 * sum(weights[a["status"]] for a in scored) / len(scored), 1)
    else:
        overall_score = 100.0

    if not assessments:
        narrative = "No control mappings were available — compliance assessment could not be performed."
    else:
        failed = sum(1 for a in assessments if a["status"] in ("FAILED", "ACTION_REQUIRED"))
        narrative = (
            f"Across {len(scored)} applicable control(s) from {len(set(a['framework'] for a in assessments))} "
            f"framework(s), {failed} control(s) require action. Overall weighted score: {overall_score}/100."
        )

    return {
        "control_assessments": assessments,
        "overall_score": overall_score,
        "critical_gaps": critical_gaps[:10],
        "evidence_checklist": evidence_checklist[:10],
        "compliance_narrative": narrative,
        "analysis_source": "deterministic_engine",
    }
