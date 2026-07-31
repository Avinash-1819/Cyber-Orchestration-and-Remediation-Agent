"""
Sentinel AI — Agent 1: Incident Triage Agent
Parses logs, extracts IOCs, enriches via VirusTotal/Shodan, classifies TP/FP,
assigns severity, and produces an Investigation Report.
"""
import re
import uuid
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, IndicatorOfCompromise, SentinelState
from app.core.exceptions import AgentError
from app.services.engines import triage_engine
from app.services.external_intel import enrich_ioc_virustotal, enrich_ip_shodan
from app.services.llm_client import MODEL_FLASH

from app.services.grafify import grafify_compress_logs

log = structlog.get_logger(__name__)

# IOC extraction patterns
_IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
_DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|info|biz|gov|mil|edu|xyz|top|club|online|site|tech)\b")
_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# Private/reserved IPs to exclude from enrichment
_PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
]


class TriageAnalysisSchema(BaseModel):
    """LLM output schema for triage analysis."""
    classification: str = Field(description="TRUE_POSITIVE or FALSE_POSITIVE")
    confidence: float = Field(description="0.0 to 1.0 classification confidence")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL")
    attack_pattern: str = Field(description="Brief description of the detected attack pattern")
    affected_assets: List[str] = Field(description="List of affected systems/users")
    key_findings: List[str] = Field(description="Key evidence points from the log")
    recommended_immediate_actions: List[str] = Field(description="Immediate containment actions")
    executive_one_liner: str = Field(description="One sentence for executive briefing")


class TriageAgent(BaseAgent):
    AGENT_NAME = "IncidentTriageAgent"

    def _extract_iocs(self, text: str) -> List[IndicatorOfCompromise]:
        """Extract IOCs from raw input text using regex patterns."""
        iocs: List[IndicatorOfCompromise] = []
        seen: set = set()

        def add_ioc(value: str, ioc_type: str):
            key = f"{value}::{ioc_type}"
            if key not in seen:
                seen.add(key)
                iocs.append(IndicatorOfCompromise(value=value, type=ioc_type))

        for ip in _IP_PATTERN.findall(text):
            if not any(p.match(ip) for p in _PRIVATE_RANGES):
                add_ioc(ip, "IP")

        for domain in _DOMAIN_PATTERN.findall(text):
            add_ioc(domain.lower(), "Domain")

        for h in _SHA256_PATTERN.findall(text):
            add_ioc(h.lower(), "Hash")
        for h in _SHA1_PATTERN.findall(text):
            if h.lower() not in [i.value for i in iocs if i.type == "Hash"]:
                add_ioc(h.lower(), "Hash")
        for h in _MD5_PATTERN.findall(text):
            if h.lower() not in [i.value for i in iocs if i.type == "Hash"]:
                add_ioc(h.lower(), "Hash")

        log.info("iocs_extracted", count=len(iocs), session_id="unknown")
        return iocs

    async def _enrich_iocs(self, iocs: List[IndicatorOfCompromise]) -> List[IndicatorOfCompromise]:
        """Enrich IOCs with VirusTotal and Shodan data. Gracefully handles unavailability."""
        enriched = []
        for ioc in iocs:
            vt_data = await enrich_ioc_virustotal(ioc.value, ioc.type)
            shodan_data = {}
            if ioc.type == "IP":
                shodan_data = await enrich_ip_shodan(ioc.value)

            enrichment = {**vt_data}
            if shodan_data:
                enrichment["shodan"] = shodan_data

            status = "ok" if vt_data.get("status") == "ok" else "unavailable"
            enriched.append(IndicatorOfCompromise(
                value=ioc.value,
                type=ioc.type,
                enrichment=enrichment,
                enrichment_status=status,
            ))
        return enriched

    async def execute(self, state: SentinelState) -> SentinelState:
        """Run triage: extract IOCs, enrich, classify, generate report."""
        self._trace(state, "extracting_iocs")

        # 1. Extract IOCs from raw input
        iocs = self._extract_iocs(state.raw_input)
        state.extracted_iocs = iocs

        self._trace(state, "enriching_iocs", {"count": len(iocs)})

        # 2. Enrich IOCs
        if iocs:
            state.extracted_iocs = await self._enrich_iocs(iocs)

        # 3. Build enrichment summary for LLM context
        enrichment_context = "\n".join([
            f"- {ioc.value} ({ioc.type}): malicious={ioc.enrichment.get('malicious', 'N/A')}, "
            f"status={ioc.enrichment_status}, ports={ioc.enrichment.get('shodan', {}).get('open_ports', [])}"
            for ioc in state.extracted_iocs[:20]
        ])

        self._trace(state, "running_llm_triage")

        # 4. LLM triage analysis (with Grafify token minimization)
        compressed_input = grafify_compress_logs(state.raw_input[:10000])

        ioc_summary = [
            {"value": ioc.value, "type": ioc.type}
            for ioc in state.extracted_iocs
        ]

        def _deterministic_triage() -> TriageAnalysisSchema:
            data = triage_engine.analyze_triage(state.raw_input, ioc_summary)
            return TriageAnalysisSchema(**data)

        prompt = f"""You are a senior threat analyst performing incident triage. 
Analyze the following security log/event data and extracted IOCs to determine if this is a True Positive or False Positive security incident.

RAW INPUT:
{compressed_input}

EXTRACTED & ENRICHED IOCs:
{enrichment_context or "No IOCs extracted — analyze the log context directly."}

Provide your triage analysis including classification, severity, key findings, and recommended actions.
Be precise and evidence-based. If the log shows no real threat indicators, classify as FALSE_POSITIVE."""

        try:
            analysis = await self.llm.generate_structured(
                prompt=prompt,
                output_schema=TriageAnalysisSchema,
                model_role=MODEL_FLASH,
                agent_name=self.AGENT_NAME,
                temperature=0.1,
                fallback_factory=_deterministic_triage,
            )
        except Exception as e:
            raise AgentError(self.AGENT_NAME, f"LLM triage analysis failed: {e}") from e

        self._trace(state, "triage_complete", {
            "classification": analysis.classification,
            "severity": analysis.severity,
            "confidence": analysis.confidence,
        })

        # 5. Create findings from analysis
        if analysis.classification == "TRUE_POSITIVE":
            finding = Finding(
                id=str(uuid.uuid4()),
                severity=analysis.severity,
                category="Incident",
                title=f"Security Incident: {analysis.attack_pattern[:100]}",
                description=f"{analysis.executive_one_liner}\n\nKey Findings:\n" +
                            "\n".join(f"• {kf}" for kf in analysis.key_findings),
                remediation_advice="\n".join(analysis.recommended_immediate_actions),
            )
            state.findings.append(finding)

        # 6. Store triage report
        state.triage_report = {
            "classification": analysis.classification,
            "confidence": analysis.confidence,
            "severity": analysis.severity,
            "attack_pattern": analysis.attack_pattern,
            "affected_assets": analysis.affected_assets,
            "key_findings": analysis.key_findings,
            "recommended_immediate_actions": analysis.recommended_immediate_actions,
            "executive_one_liner": analysis.executive_one_liner,
            "ioc_count": len(state.extracted_iocs),
            "iocs_enriched": [
                {"value": ioc.value, "type": ioc.type, "status": ioc.enrichment_status,
                 "malicious": ioc.enrichment.get("malicious", "N/A")}
                for ioc in state.extracted_iocs
            ],
        }

        return state
