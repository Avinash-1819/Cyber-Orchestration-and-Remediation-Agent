"""
Sentinel AI — Agent 11: Network Security Agent
Network exposure assessment from the actual payload: IP:port pairs, known-risk
service ratings, and concrete firewall hardening rules for the exposure found.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.services.engines import network_security_engine
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class NetworkSecurityAgent(BaseAgent):
    AGENT_NAME = "NetworkSecurityAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "assessing_network_exposure")

        ioc_summary = [
            {"value": i.value, "type": i.type, "enrichment": i.enrichment}
            for i in state.extracted_iocs
        ]
        report = network_security_engine.analyze_network_security(state.raw_input, ioc_summary)

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "You are a network security engineer. In 2-3 sentences, describe the "
                    "exposure risk and what firewall changes should be prioritized.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("network_security_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        state.network_security_report = report

        for service in report.get("exposed_services", []):
            if service.get("risk") in ("CRITICAL", "HIGH"):
                state.findings.append(Finding(
                    id=str(__import__("uuid").uuid4()),
                    severity=service.get("risk", "HIGH"),
                    category="Network",
                    title=f"Exposed {service.get('service')} on port {service.get('port')}",
                    description=(
                        f"Service '{service.get('service')}' on TCP/{service.get('port')} is "
                        "assessed as high-risk when exposed to untrusted networks."
                    ),
                    remediation_advice="Apply the generated firewall hardening rule or move the service behind a VPN/zero-trust proxy.",
                ))

        self._trace(state, "network_assessment_complete", {
            "exposed_services": len(report.get("exposed_services", [])),
            "exposure_risk": report.get("overall_exposure_risk"),
            "hardening_rules": len(report.get("hardening_rules", [])),
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        services = len(report.get("exposed_services", []))
        if services == 0:
            return (
                "No explicit port exposure was found in the payload. Maintain a default-deny "
                "perimeter posture."
            )
        return (
            f"{services} exposed service(s) assessed; overall exposure risk is "
            f"{report.get('overall_exposure_risk')}. Apply the generated hardening rules "
            "for critical/high exposure."
        )
