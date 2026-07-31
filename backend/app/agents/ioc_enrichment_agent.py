"""
Sentinel AI — Agent 7: IOC Enrichment Agent
Enriches extracted indicators with external threat intelligence (VirusTotal, Shodan
when keys are configured) plus a deterministic offline analysis (hash algorithm/
entropy, IP classification, domain TLD risk). Verdicts are honest — 'malicious'
is only assigned with external confirmation; otherwise 'inconclusive'.
"""
import structlog

from app.agents.base_agent import BaseAgent
from app.agents.state import SentinelState
from app.services.engines import ioc_enrichment_engine
from app.services.external_intel import enrich_ip_shodan, enrich_ioc_virustotal
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)


class IOCEnrichmentAgent(BaseAgent):
    AGENT_NAME = "IOCEnrichmentAgent"

    async def _external_lookup(self, ioc) -> dict:
        """Real external enrichment when keys are configured. Returns {} on unavailability."""
        vt = await enrich_ioc_virustotal(ioc.value, ioc.type)
        merged = {**vt}
        if ioc.type == "IP":
            shodan = await enrich_ip_shodan(ioc.value)
            if shodan.get("status") == "ok":
                merged["shodan"] = shodan
        return merged

    async def execute(self, state: SentinelState) -> SentinelState:
        self._trace(state, "enriching_indicators", {"count": len(state.extracted_iocs)})

        # If upstream triage already populated enrichment, use it; else look up fresh.
        ioc_records = []
        for ioc in state.extracted_iocs:
            external = ioc.enrichment or {}
            if ioc.enrichment_status != "ok" or not external:
                external = await self._external_lookup(ioc)
            ioc_records.append({
                "value": ioc.value,
                "type": ioc.type,
                "enrichment": ioc.enrichment,
                "external": external,
            })

        report = ioc_enrichment_engine.analyze_ioc_enrichment(ioc_records)

        narrative = self._narrative_text(report)
        if self.llm.is_configured:
            try:
                prompt = (
                    "Summarize the following IOC enrichment results for a SOC analyst in 2-3 sentences, "
                    "highlighting which indicators carry real confirmation and which need external feeds.\n\n"
                    f"{report}"
                )
                llm_text = await self.llm.generate_text(
                    prompt=prompt, model_role=MODEL_FLASH, agent_name=self.AGENT_NAME, temperature=0.2
                )
                if llm_text.strip():
                    narrative = llm_text.strip()
            except Exception as e:
                log.warning("ioc_enrichment_llm_narrative_failed", error=str(e))

        report["narrative"] = narrative
        report["ioc_count"] = len(state.extracted_iocs)

        # Persist enrichment back onto the state IOCs for downstream agents
        by_value = {a["value"]: a for a in report.get("ioc_analyses", [])}
        for ioc in state.extracted_iocs:
            analysis = by_value.get(ioc.value)
            if analysis:
                ioc.enrichment["verdict"] = analysis.get("verdict")
                ioc.enrichment["confidence"] = analysis.get("confidence")
                ioc.enrichment["heuristic"] = analysis.get("heuristic")

        state.ioc_enrichment_report = report

        self._trace(state, "enrichment_complete", {
            "total": report["overall"]["total"],
            "malicious": report["overall"]["malicious"],
            "suspicious": report["overall"]["suspicious"],
        })

        return state

    def _narrative_text(self, report: dict) -> str:
        o = report.get("overall", {})
        if o.get("malicious"):
            return (
                f"Enrichment confirmed {o['malicious']} malicious indicator(s) and flagged "
                f"{o['suspicious']} suspicious. These should be treated as active threats."
            )
        if o.get("suspicious"):
            return (
                f"{o['suspicious']} indicator(s) carry elevated-risk signals; treat as suspicious "
                "until external feeds confirm."
            )
        if o.get("total", 0) == 0:
            return "No indicators were present to enrich."
        return (
            "No indicator received a confirmed malicious verdict from available sources. "
            "External intelligence feeds (VirusTotal/Shodan) require API keys; offline "
            "heuristic analysis is included for context."
        )
