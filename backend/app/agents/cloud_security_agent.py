"""
Sentinel AI — Agent 10: Cloud Security Agent
Cloud posture audit of the actual IaC payload (Terraform / CloudFormation /
Kubernetes): public exposure, wildcard IAM, missing encryption, container
privilege issues. Leverages the file snippets collected by the DevSecOps agent
so repo scans are analyzed without re-cloning.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.services.engines import cloud_security_engine
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class CloudSecurityAgent(BaseAgent):
    AGENT_NAME = "CloudSecurityAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "auditing_cloud_posture")

        # Use file snippets collected by DevSecOps when available; else analyze raw input.
        files = []
        code_report = state.code_audit_report or {}
        snippets = code_report.get("file_snippets") or []
        if snippets:
            files = [(s["path"], s["content"]) for s in snippets]
        else:
            files = [("input_code", state.raw_input)]

        report = cloud_security_engine.analyze_cloud_security(files)

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "You are a cloud security architect. In 2-3 sentences, explain the most "
                    "important cloud misconfiguration(s) found and their business impact.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("cloud_security_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        state.cloud_security_report = report

        # Promote misconfigurations to findings
        for m in report.get("misconfigurations", []):
            state.findings.append(Finding(
                id=str(__import__("uuid").uuid4()),
                severity=m.get("severity", "MEDIUM"),
                category=m.get("category", "Cloud"),
                title=m.get("title", "Cloud misconfiguration"),
                description=m.get("description", ""),
                file_path=m.get("file_path"),
                line_number=m.get("line_number"),
                remediation_advice=m.get("remediation_advice", ""),
            ))

        self._trace(state, "cloud_audit_complete", {
            "misconfigurations": len(report.get("misconfigurations", [])),
            "risk": report.get("overall_risk_level"),
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        count = len(report.get("misconfigurations", []))
        if count == 0:
            return (
                "No cloud misconfigurations matched the rule set. Maintain this baseline "
                "and re-audit on every infrastructure change."
            )
        return (
            f"The cloud posture audit identified {count} misconfiguration(s) with an "
            f"overall risk of {report.get('overall_risk_level')}. Remediate the "
            "critical/high items before the next release window."
        )
