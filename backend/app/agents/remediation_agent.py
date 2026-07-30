"""
Sentinel AI — Agent 2: Incident Remediation Agent
Generates platform-specific remediation playbooks with destructive action flagging.
HARD ARCHITECTURAL BOUNDARY: This agent generates text/scripts only.
The backend NEVER executes any remediation command. Ever.
"""
import uuid
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.core.exceptions import AgentError
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class RemediationStep(BaseModel):
    """A single remediation step with platform and destructive flag."""
    step_number: int
    platform: str  # linux, windows, aws, general
    title: str
    description: str
    command: Optional[str] = None  # The command text (never executed by backend)
    destructive: bool  # If True, requires human approval in UI
    rollback_command: Optional[str] = None  # Inverse/undo command
    requires_human_approval: bool
    estimated_time_minutes: int


class RemediationPlaybook(BaseModel):
    """Complete remediation playbook output schema."""
    incident_summary: str
    risk_level: str
    containment_steps: List[RemediationStep]
    eradication_steps: List[RemediationStep]
    recovery_steps: List[RemediationStep]
    lessons_learned: List[str]
    estimated_total_time_minutes: int


class RemediationAgent(BaseAgent):
    AGENT_NAME = "RemediationAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        """Generate remediation playbooks for detected incidents."""
        if not state.triage_report:
            state.add_error(self.AGENT_NAME, "No triage report available — skipping remediation")
            return state

        triage = state.triage_report
        if triage.get("classification") == "FALSE_POSITIVE":
            self._trace(state, "skipped_false_positive")
            state.remediation_plan = {"status": "not_required", "reason": "Incident classified as False Positive"}
            return state

        self._trace(state, "generating_playbook", {
            "severity": triage.get("severity"),
            "attack": triage.get("attack_pattern"),
        })

        # Build IOC context
        ioc_context = "\n".join([
            f"- {ioc['value']} ({ioc['type']}): malicious={ioc.get('malicious', 'N/A')}"
            for ioc in triage.get("iocs_enriched", [])[:15]
        ])

        prompt = f"""You are a senior incident responder. Generate a comprehensive remediation playbook for this security incident.

INCIDENT SUMMARY:
- Classification: {triage.get("classification")}
- Severity: {triage.get("severity")}
- Attack Pattern: {triage.get("attack_pattern")}
- Affected Assets: {", ".join(triage.get("affected_assets", []))}
- Key Findings: {"; ".join(triage.get("key_findings", []))}

COMPROMISED IOCs:
{ioc_context or "See key findings above"}

REQUIREMENTS:
1. Provide containment steps (stop the bleeding), eradication steps (remove the threat), and recovery steps (restore normal operations)
2. Cover ALL applicable platforms: Linux (iptables/nftables/systemd/quarantine), Windows (PowerShell/registry/local firewall/AD containment), AWS (IAM revocation/Security Group tightening/S3 policy)
3. For EVERY command that could disrupt services or delete data, set destructive=true and requires_human_approval=true
4. Include rollback_command for every destructive action
5. Be specific with actual command syntax, not pseudocode
6. Flag any step that requires coordination with another team

IMPORTANT: The backend will ONLY display these commands — it will NEVER execute them. Mark destructive=true conservatively."""

        try:
            playbook = await self.llm.generate_structured(
                prompt=prompt,
                output_schema=RemediationPlaybook,
                model_role=MODEL_FLASH,
                agent_name=self.AGENT_NAME,
                temperature=0.1,
            )
        except Exception as e:
            raise AgentError(self.AGENT_NAME, f"Playbook generation failed: {e}") from e

        self._trace(state, "playbook_generated", {
            "total_steps": len(playbook.containment_steps) + len(playbook.eradication_steps) + len(playbook.recovery_steps),
            "destructive_steps": sum(1 for s in [*playbook.containment_steps, *playbook.eradication_steps, *playbook.recovery_steps] if s.destructive),
        })

        # Create findings for destructive remediation steps (for UI approval workflow)
        all_steps = [*playbook.containment_steps, *playbook.eradication_steps, *playbook.recovery_steps]
        for step in all_steps:
            if step.destructive:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    severity="HIGH",
                    category="Remediation",
                    title=f"[REQUIRES APPROVAL] {step.title}",
                    description=step.description,
                    remediation_advice=step.command or "",
                    destructive=True,
                )
                state.findings.append(finding)

        # Store full playbook
        state.remediation_plan = playbook.model_dump()

        return state
