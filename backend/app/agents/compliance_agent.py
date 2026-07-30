"""
Sentinel AI — Agent 4: Compliance Agent (GRC)
Maps findings to ISO 27001, SOC 2 Type II, NIST SP 800-53, PCI DSS 4.0.
Uses a versioned, human-editable YAML seed file for control mappings —
the LLM applies mappings and writes rationale, but NEVER invents control IDs.
"""
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog
import yaml
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.core.config import settings
from app.core.exceptions import AgentError
from app.services.llm_client import MODEL_PRO

log = structlog.get_logger(__name__)

# Compliance frameworks we support
FRAMEWORKS = ["ISO27001", "SOC2", "NIST_800_53", "PCI_DSS_4"]


def _load_control_mappings() -> Dict[str, Any]:
    """Load all compliance control mapping YAML files."""
    mappings = {}
    mapping_dir = Path(settings.COMPLIANCE_MAPPINGS_DIR)
    if not mapping_dir.exists():
        mapping_dir = Path(__file__).resolve().parent.parent.parent / "data" / "compliance_mappings"

    if not mapping_dir.exists():
        log.warning("compliance_mappings_dir_missing", path=str(mapping_dir))
        return {}

    for framework_file in mapping_dir.glob("*.yaml"):
        framework_name = framework_file.stem
        try:
            with open(framework_file, "r", encoding="utf-8") as f:
                mappings[framework_name] = yaml.safe_load(f)
            log.debug("compliance_mapping_loaded", framework=framework_name)
        except Exception as e:
            log.error("compliance_mapping_load_error", file=str(framework_file), error=str(e))

    return mappings


class ControlAssessment(BaseModel):
    """Assessment of a single compliance control."""
    control_id: str
    control_name: str
    framework: str
    status: str  # PASSED, FAILED, ACTION_REQUIRED, NOT_APPLICABLE
    rationale: str
    related_finding_ids: List[str] = Field(description="IDs of findings related to this control")


class ComplianceAnalysisSchema(BaseModel):
    """LLM output schema for compliance mapping."""
    control_assessments: List[ControlAssessment]
    overall_score: float = Field(description="0.0 to 100.0 compliance score")
    critical_gaps: List[str] = Field(description="Most critical compliance gaps")
    evidence_checklist: List[str] = Field(description="Items an auditor would need as evidence")
    compliance_narrative: str = Field(description="Summary suitable for a compliance officer")


class ComplianceAgent(BaseAgent):
    AGENT_NAME = "ComplianceAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        """Map findings to compliance frameworks and compute scores."""
        if not state.code_audit_report and not state.triage_report and not state.findings:
            state.add_error(self.AGENT_NAME, "No findings or upstream reports to assess compliance against")
            return state

        self._trace(state, "loading_control_mappings")

        # 1. Load versioned control mappings (LLM does NOT invent these)
        control_mappings = _load_control_mappings()

        # Serialize mappings for LLM context
        mapping_context = yaml.dump(control_mappings, default_flow_style=False)[:6000]  # Truncate for token limits

        # 2. Build findings context
        findings_context = "\n".join([
            f"- [{f.severity}] {f.category}: {f.title}"
            for f in state.findings[:50]
        ])

        # 3. Build upstream reports context
        reports_context = ""
        if state.code_audit_report:
            reports_context += f"\nCODE AUDIT:\n- Risk: {state.code_audit_report.get('overall_risk_level')}\n- Summary: {state.code_audit_report.get('summary', '')[:500]}"
        if state.triage_report:
            reports_context += f"\nINCIDENT TRIAGE:\n- Classification: {state.triage_report.get('classification')}\n- Severity: {state.triage_report.get('severity')}\n- Pattern: {state.triage_report.get('attack_pattern', '')[:300]}"

        self._trace(state, "running_compliance_mapping_llm")

        prompt = f"""You are a senior GRC (Governance, Risk, Compliance) analyst assessing security findings against multiple compliance frameworks.

IMPORTANT: Use ONLY the control IDs provided in the CONTROL MAPPINGS below. Do NOT invent, guess, or hallucinate any control IDs.

CONTROL MAPPINGS (finding-category → framework control ID):
{mapping_context}

SECURITY FINDINGS FROM THIS SCAN:
{findings_context or "No specific findings — assess general posture from reports."}

UPSTREAM REPORTS:
{reports_context}

FRAMEWORKS TO ASSESS: ISO 27001:2022, SOC 2 Type II (Trust Services Criteria), NIST SP 800-53 Rev 5, PCI DSS 4.0

For each relevant control from the mappings:
1. Determine PASSED/FAILED/ACTION_REQUIRED based on the evidence in findings
2. Write a brief rationale citing specific findings
3. List the finding IDs that triggered this assessment

Calculate an overall compliance score (0-100) where:
- 100 = all controls PASSED
- 0 = all controls FAILED
- Weight CRITICAL/HIGH failures more heavily

Produce an auditor evidence checklist of specific artifacts an auditor would need."""

        try:
            compliance = await self.llm.generate_structured(
                prompt=prompt,
                output_schema=ComplianceAnalysisSchema,
                model_role=MODEL_PRO,  # Use Pro for deep GRC reasoning
                agent_name=self.AGENT_NAME,
                temperature=0.1,
            )
        except Exception as e:
            raise AgentError(self.AGENT_NAME, f"Compliance analysis failed: {e}") from e

        self._trace(state, "compliance_complete", {
            "score": compliance.overall_score,
            "controls_assessed": len(compliance.control_assessments),
        })

        # 4. Update findings with framework control references
        control_id_map = {a.control_id: a for a in compliance.control_assessments}
        for finding in state.findings:
            # Map findings to controls based on category
            matching_controls = [
                a.control_id for a in compliance.control_assessments
                if finding.id in a.related_finding_ids or finding.category in a.rationale
            ]
            finding.framework_controls.extend(matching_controls[:5])

        # 5. Create findings for FAILED compliance controls
        for assessment in compliance.control_assessments:
            if assessment.status in ("FAILED", "ACTION_REQUIRED"):
                finding = Finding(
                    id=str(uuid.uuid4()),
                    severity="MEDIUM" if assessment.status == "ACTION_REQUIRED" else "HIGH",
                    category=f"Compliance-{assessment.framework}",
                    title=f"[{assessment.framework}] {assessment.control_id}: {assessment.control_name}",
                    description=assessment.rationale,
                    remediation_advice=f"Address the control gap for {assessment.control_id} ({assessment.framework})",
                    framework_controls=[f"{assessment.framework}:{assessment.control_id}"],
                )
                state.findings.append(finding)

        state.compliance_report = {
            "overall_score": compliance.overall_score,
            "critical_gaps": compliance.critical_gaps,
            "evidence_checklist": compliance.evidence_checklist,
            "compliance_narrative": compliance.compliance_narrative,
            "control_assessments": [a.model_dump() for a in compliance.control_assessments],
            "frameworks_assessed": FRAMEWORKS,
            "controls_passed": sum(1 for a in compliance.control_assessments if a.status == "PASSED"),
            "controls_failed": sum(1 for a in compliance.control_assessments if a.status in ("FAILED", "ACTION_REQUIRED")),
        }

        return state
