"""
Sentinel AI — Agent 12: Risk Scoring Agent
Quantitative risk quantification from the actual state: severity-weighted impact,
evidence-based likelihood, 5x5 matrix placement, top-risk ranking, and a single
0-10 risk score. Feeds the Executive Reporting agent's posture assessment.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import SentinelState
from app.services.engines import risk_scoring_engine
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class RiskScoringAgent(BaseAgent):
    AGENT_NAME = "RiskScoringAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "computing_risk_score")

        report = risk_scoring_engine.analyze_risk(state.model_dump(mode="json"))

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "You are a CISO advisor. In 2-3 sentences, interpret this quantitative "
                    "risk score for a decision-maker and name the top risk to address first.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("risk_scoring_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        state.risk_report = report

        self._trace(state, "risk_score_computed", {
            "score": report.get("risk_score"),
            "posture": report.get("posture"),
            "matrix": report.get("matrix_cell", {}).get("level"),
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        return (
            f"Quantitative risk score is {report.get('risk_score')}/10 "
            f"({report.get('posture')}) on a 5x5 matrix "
            f"(row {report.get('matrix_cell', {}).get('row')}, "
            f"column {report.get('matrix_cell', {}).get('column')}). "
            "Address the highest-ranked risk first."
        )
