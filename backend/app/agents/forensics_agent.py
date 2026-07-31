"""
Sentinel AI — Agent 9: Forensics Agent
Digital-forensics triage of the submitted artifacts: hash identification and
entropy, event-timeline reconstruction, artifact classification, and a
chain-of-custody record. All analysis is derived from the actual payload.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import SentinelState
from app.services.engines import forensics_engine
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class ForensicsAgent(BaseAgent):
    AGENT_NAME = "ForensicsAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "forensic_triage")

        ioc_summary = [
            {"value": i.value, "type": i.type} for i in state.extracted_iocs
        ]
        report = forensics_engine.analyze_forensics(state.raw_input, ioc_summary)

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "You are a digital forensics examiner. In 2-3 sentences, summarize what "
                    "evidence is available, what integrity checks were performed, and the "
                    "highest-priority next acquisition step.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("forensics_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        state.forensics_report = report

        self._trace(state, "forensics_complete", {
            "artifacts": len(report.get("artifacts", [])),
            "timeline_entries": len(report.get("event_timeline", [])),
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        artifacts = len(report.get("artifacts", []))
        timeline = len(report.get("event_timeline", []))
        return (
            f"Forensic triage catalogued {artifacts} artifact(s) and reconstructed "
            f"{timeline} timeline entr{'y' if timeline == 1 else 'ies'}. Preserve "
            "volatile evidence before any remediation actions."
        )
