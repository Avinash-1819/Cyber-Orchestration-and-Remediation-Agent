"""
Sentinel AI — Agent 8: Log Correlation Agent
SIEM-style correlation of the submitted log payload: event timelines, attack
sequence detection (brute force, port scan, privilege escalation, exfiltration),
and MITRE ATT&CK kill-chain coverage. All findings derive from the actual logs.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.services.engines import log_correlation_engine
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class LogCorrelationAgent(BaseAgent):
    AGENT_NAME = "LogCorrelationAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "correlating_logs")

        ioc_summary = [
            {"value": i.value, "type": i.type} for i in state.extracted_iocs
        ]
        report = log_correlation_engine.analyze_log_correlation(state.raw_input, ioc_summary)

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "You are a SOC lead. In 2-3 sentences, explain the correlated attack "
                    "picture from these detected sequences and what the analyst should do first.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("log_correlation_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        state.log_correlation_report = report

        # Promote high/critical sequences to findings for the unified view
        for seq in report.get("detected_sequences", []):
            if seq.get("severity") in ("CRITICAL", "HIGH"):
                state.findings.append(Finding(
                    id=str(__import__("uuid").uuid4()),
                    severity=seq.get("severity", "HIGH"),
                    category="LogCorrelation",
                    title=f"{seq.get('type', 'sequence')} from {seq.get('source', 'unknown')}",
                    description=seq.get("detail", ""),
                    remediation_advice="Correlate with perimeter logs; block the source and hunt for related indicators.",
                ))

        self._trace(state, "correlation_complete", {
            "sequences": len(report.get("detected_sequences", [])),
            "severity": report.get("overall_severity"),
            "events_parsed": report.get("total_events_parsed"),
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        seqs = report.get("detected_sequences", [])
        if not seqs:
            return (
                "No attack sequences were detected in the submitted logs. The payload "
                "was parsed and kill-chain coverage assessed as informational."
            )
        return (
            f"{len(seqs)} correlated sequence(s) detected at {report.get('overall_severity')} severity. "
            "Prioritize the critical/high sequences and correlate with perimeter telemetry."
        )
