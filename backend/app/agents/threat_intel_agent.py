"""
Sentinel AI — Agent 5: Threat Intelligence Agent
CVE lookup (NVD), MITRE ATT&CK mapping (local STIX), Sigma/YARA/Splunk SPL generation.
"""
import re
import uuid
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.core.exceptions import AgentError
from app.services.external_intel import get_cve, search_mitre_techniques
from app.services.llm_client import MODEL_FLASH

log = structlog.get_logger(__name__)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class DetectionRule(BaseModel):
    rule_type: str  # sigma, yara, splunk_spl
    name: str
    description: str
    rule_content: str


class TechniqueMapping(BaseModel):
    id: str = Field(description="MITRE ATT&CK ID e.g. T1566.001")
    name: str = Field(description="Technique name")
    tactic: str = Field(description="MITRE tactic e.g. Initial Access")
    description: str = Field(description="Brief description")


class ThreatIntelSchema(BaseModel):
    """LLM output schema for threat intelligence analysis."""
    threat_summary: str
    attack_techniques: List[TechniqueMapping] = Field(
        description="List of mapped MITRE ATT&CK techniques"
    )
    exploitability_assessment: str = Field(
        description="Assessment of active exploitation, PoC availability, and weaponization"
    )
    affected_products: List[str] = Field(description="List of affected software/hardware products")
    detection_rules: List[DetectionRule]
    threat_actor_context: str = Field(description="Known threat actor attribution if available")
    intelligence_confidence: str = Field(description="HIGH, MEDIUM, or LOW confidence in the intel")


class ThreatIntelAgent(BaseAgent):
    AGENT_NAME = "ThreatIntelAgent"

    def _extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text."""
        return list(set(m.upper() for m in CVE_PATTERN.findall(text)))

    async def execute(self, state: SentinelState) -> SentinelState:
        """Run threat intelligence analysis."""
        self._trace(state, "extracting_cve_ids")

        # 1. Extract CVE IDs from input and existing findings
        all_text = state.raw_input + " ".join(
            f.description for f in state.findings
        )
        cve_ids = self._extract_cve_ids(all_text)

        self._trace(state, "cve_ids_found", {"count": len(cve_ids), "ids": cve_ids[:10]})

        # 2. Query NVD for CVE data (with caching + backoff)
        cve_data_map = {}
        for cve_id in cve_ids[:20]:  # Cap at 20 to respect rate limits
            cve_data = await get_cve(cve_id)
            cve_data_map[cve_id] = cve_data
            if cve_data.get("status") == "found":
                self._trace(state, "cve_fetched", {
                    "cve_id": cve_id,
                    "score": cve_data.get("cvss_v3_score"),
                    "severity": cve_data.get("cvss_v3_severity"),
                })

        # 3. Search MITRE ATT&CK (local dataset)
        self._trace(state, "searching_mitre_attack")
        keywords = []
        if state.triage_report:
            keywords.extend(state.triage_report.get("attack_pattern", "").split()[:5])
        keywords.extend(cve_ids[:3])

        mitre_techniques = search_mitre_techniques(keywords) if keywords else []
        self._trace(state, "mitre_techniques_found", {"count": len(mitre_techniques)})

        # 4. Build comprehensive context for LLM
        cve_context = ""
        for cve_id, data in cve_data_map.items():
            if data.get("status") == "found":
                cve_context += (
                    f"\n{cve_id}: CVSS {data.get('cvss_v3_score')} ({data.get('cvss_v3_severity')})\n"
                    f"  Description: {data.get('description', '')[:300]}\n"
                    f"  Vector: {data.get('cvss_v3_vector', 'N/A')}\n"
                    f"  Published: {data.get('published', 'N/A')}\n"
                )

        mitre_context = "\n".join([
            f"- {t['id']} ({t['name']}): Tactics={', '.join(t.get('tactics', []))}"
            for t in mitre_techniques
        ])

        incident_context = ""
        if state.triage_report:
            incident_context = f"""
INCIDENT CONTEXT:
- Attack Pattern: {state.triage_report.get('attack_pattern', 'N/A')}
- Severity: {state.triage_report.get('severity', 'N/A')}
- IOCs: {len(state.extracted_iocs)} indicators
"""

        self._trace(state, "running_threat_intel_llm")

        prompt = f"""You are a senior threat intelligence analyst. Analyze the following security data and produce actionable threat intelligence.

RAW INPUT (may contain CVE IDs, malware names, or threat hunt requests):
{state.raw_input[:3000]}

CVE DATA FROM NVD:
{cve_context or "No CVEs found or NVD unavailable"}

MITRE ATT&CK TECHNIQUES (from local STIX dataset):
{mitre_context or "No matching techniques found"}

{incident_context}

PRODUCE:
1. A threat summary linking all the data together
2. Mapped MITRE ATT&CK techniques (use ONLY the IDs from the MITRE data above, or well-known IDs like T1566.001 you are certain of)
3. Exploitability assessment (Is there active exploitation? Public PoC? Weaponized?)
4. Detection rules:
   - 1 Sigma rule (YAML format, valid sigma v1 syntax)
   - 1 YARA rule (valid YARA syntax)
   - 1 Splunk SPL query
5. Threat actor context if attribution is possible from the data

For detection rules, be specific to the threat — generic rules add no value."""

        try:
            intel = await self.llm.generate_structured(
                prompt=prompt,
                output_schema=ThreatIntelSchema,
                model_role=MODEL_FLASH,
                agent_name=self.AGENT_NAME,
                temperature=0.1,
            )
        except Exception as e:
            raise AgentError(self.AGENT_NAME, f"Threat intel LLM analysis failed: {e}") from e

        self._trace(state, "threat_intel_complete", {
            "techniques": len(intel.attack_techniques),
            "rules_generated": len(intel.detection_rules),
            "confidence": intel.intelligence_confidence,
        })

        # 5. Create findings for high-severity CVEs
        for cve_id, data in cve_data_map.items():
            if data.get("status") == "found":
                score = data.get("cvss_v3_score") or 0
                if score >= 7.0:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        severity="CRITICAL" if score >= 9.0 else "HIGH",
                        category="CVE",
                        title=f"{cve_id}: {data.get('description', '')[:80]}",
                        description=f"CVSS v3 Score: {score} ({data.get('cvss_v3_severity')})\n"
                                    f"Vector: {data.get('cvss_v3_vector', 'N/A')}\n\n"
                                    f"{data.get('description', '')}",
                        remediation_advice=f"Apply vendor patch for {cve_id}. References: {', '.join(data.get('references', [])[:2])}",
                    )
                    state.findings.append(finding)

        state.threat_intel_report = {
            "threat_summary": intel.threat_summary,
            "attack_techniques": [t.model_dump() for t in intel.attack_techniques],
            "exploitability": intel.exploitability_assessment,
            "affected_products": intel.affected_products,
            "detection_rules": [r.model_dump() for r in intel.detection_rules],
            "threat_actor_context": intel.threat_actor_context,
            "confidence": intel.intelligence_confidence,
            "cve_data": list(cve_data_map.values()),
            "mitre_techniques_matched": mitre_techniques,
        }

        return state
