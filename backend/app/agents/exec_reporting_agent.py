"""
Sentinel AI — Agent 6: Executive Reporting Agent
Translates all technical findings into C-suite business risk language
and triggers PDF/Markdown/JSON report generation.
This agent ALWAYS runs last, regardless of pipeline.
"""
import uuid
from typing import Any, Dict, List, Optional

import structlog
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.core.exceptions import AgentError
from app.services.llm_client import MODEL_PRO
from app.services.report_engine import generate_all_reports

log = structlog.get_logger(__name__)


class ExecutiveSummarySchema(BaseModel):
    """LLM output schema for executive reporting."""
    executive_headline: str = Field(description="One-sentence board-level summary")
    executive_narrative: str = Field(
        description="3-5 paragraph narrative for CISO/CIO/CTO. Business impact, financial risk, operational risk. No technical jargon."
    )
    business_impact_summary: str = Field(description="Financial and operational risk assessment in dollar/business terms")
    key_recommendations: List[str] = Field(
        description="Top 5 strategic recommendations ordered by priority"
    )
    immediate_actions_required: List[str] = Field(
        description="Actions needed in the next 24-48 hours"
    )
    risk_posture: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW — overall organizational risk posture")
    regulatory_exposure: str = Field(
        description="Exposure to regulatory fines, breach notifications, or audit failures"
    )
    estimated_remediation_effort: str = Field(
        description="Rough estimate of team-hours and timeline to full remediation"
    )


class ExecReportingAgent(BaseAgent):
    AGENT_NAME = "ExecReportingAgent"

    async def execute(self, state: SentinelState) -> SentinelState:
        """Generate executive summary and compile all report artifacts."""
        self._trace(state, "building_executive_summary")

        # Compile findings summary
        summary = state.finding_summary
        finding_details = "\n".join([
            f"- [{f.severity}] {f.category}: {f.title}"
            for f in state.findings[:30]
        ])

        # Build comprehensive context from all upstream agents
        context_parts = []
        if state.triage_report:
            context_parts.append(f"""
INCIDENT TRIAGE:
- Classification: {state.triage_report.get('classification')}
- Severity: {state.triage_report.get('severity')}
- Attack Pattern: {state.triage_report.get('attack_pattern', 'N/A')}
- Affected Assets: {', '.join(state.triage_report.get('affected_assets', []))}
- Executive Summary: {state.triage_report.get('executive_one_liner', '')}
""")

        if state.code_audit_report:
            context_parts.append(f"""
CODE/INFRASTRUCTURE AUDIT:
- Overall Risk: {state.code_audit_report.get('overall_risk_level')}
- SAST Findings: {state.code_audit_report.get('sast_findings_count', 0)}
- Secrets Exposed: {state.code_audit_report.get('secrets_findings_count', 0)}
- Summary: {state.code_audit_report.get('summary', '')[:400]}
""")

        if state.compliance_report:
            context_parts.append(f"""
COMPLIANCE STATUS:
- Score: {state.compliance_report.get('overall_score', 0):.1f}/100
- Controls Failed: {state.compliance_report.get('controls_failed', 0)}
- Critical Gaps: {'; '.join(state.compliance_report.get('critical_gaps', [])[:3])}
""")

        if state.threat_intel_report:
            context_parts.append(f"""
THREAT INTELLIGENCE:
- Threat Summary: {state.threat_intel_report.get('threat_summary', '')[:300]}
- Exploitability: {state.threat_intel_report.get('exploitability', 'N/A')}
- Confidence: {state.threat_intel_report.get('confidence', 'N/A')}
""")

        aggregate_context = "\n".join(context_parts)

        prompt = f"""You are the CISO of a Fortune 500 company briefing the board of directors on a security incident/assessment.

Your audience: CEO, CFO, General Counsel, CIO, CTO, Board members. They are NOT technical but ARE responsible for risk.

FINDING COUNTS:
- CRITICAL: {summary['CRITICAL']}
- HIGH: {summary['HIGH']}
- MEDIUM: {summary['MEDIUM']}
- LOW: {summary['LOW']}
- INFORMATIONAL: {summary['INFORMATIONAL']}
- Total: {summary['total']}

PIPELINE EXECUTED: {state.pipeline}

TECHNICAL DETAILS (translate these to business impact):
{aggregate_context}

TOP FINDINGS:
{finding_details or "No specific findings recorded."}

PRODUCE:
1. A board-ready executive narrative (NO technical jargon — speak in terms of business risk, financial exposure, customer trust, regulatory risk)
2. Business impact in concrete terms (data at risk, potential fine amounts if relevant, service disruption impact)
3. Regulatory exposure (GDPR, CCPA, HIPAA, PCI DSS, SOX — whichever applies)
4. Top 5 strategic recommendations ordered by business priority
5. Immediate 24-48 hour actions
6. Estimated remediation effort in business terms (weeks, team size, approximate cost range)

If findings are minimal, be honest about the positive security posture — don't inflate risk."""

        try:
            exec_summary = await self.llm.generate_structured(
                prompt=prompt,
                output_schema=ExecutiveSummarySchema,
                model_role=MODEL_PRO,  # Pro model for nuanced business synthesis
                agent_name=self.AGENT_NAME,
                temperature=0.2,
            )
        except Exception as e:
            raise AgentError(self.AGENT_NAME, f"Executive summary generation failed: {e}") from e

        self._trace(state, "executive_summary_generated", {
            "risk_posture": exec_summary.risk_posture,
            "headline": exec_summary.executive_headline[:80],
        })

        state.executive_summary = {
            "executive_headline": exec_summary.executive_headline,
            "executive_narrative": exec_summary.executive_narrative,
            "business_impact_summary": exec_summary.business_impact_summary,
            "key_recommendations": exec_summary.key_recommendations,
            "immediate_actions_required": exec_summary.immediate_actions_required,
            "risk_posture": exec_summary.risk_posture,
            "regulatory_exposure": exec_summary.regulatory_exposure,
            "estimated_remediation_effort": exec_summary.estimated_remediation_effort,
        }

        # Generate all report artifacts
        self._trace(state, "generating_reports")
        try:
            paths = generate_all_reports(state)
            state.report_pdf_path = paths.get("pdf")
            state.report_markdown_path = paths.get("markdown")
            state.report_json_path = paths.get("json")
            self._trace(state, "reports_generated", {
                "pdf": state.report_pdf_path,
                "markdown": state.report_markdown_path,
                "json": state.report_json_path,
            })
        except Exception as e:
            state.add_error(self.AGENT_NAME, f"Report generation partial failure: {e}")

        state.status = "completed"
        return state
