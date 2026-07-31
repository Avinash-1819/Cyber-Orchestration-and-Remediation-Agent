"""
Sentinel AI — Centralized Shared State Schema (Pydantic v2)
This is the single source of truth that flows through the LangGraph state machine.
Every agent reads from and writes back to SentinelState.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IndicatorOfCompromise(BaseModel):
    value: str
    type: str  # IP, Domain, Hash, Username
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    enrichment_status: str = "pending"  # pending | ok | unavailable


class Finding(BaseModel):
    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    category: str
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation_advice: Optional[str] = None
    destructive: bool = False  # Only meaningful for remediation-plan-derived findings
    framework_controls: List[str] = Field(default_factory=list)  # e.g. ["ISO27001:A.12.6", "NIST:SI-2"]


class ExecutionTraceEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent: str
    event: str
    details: Dict[str, Any] = Field(default_factory=dict)


class SentinelState(BaseModel):
    session_id: str
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_input: str
    input_type: str  # CODE, LOGS, REPO_URL, CVE, IOC, MIXED
    pipeline: str  # A, B, C, or A_THEN_B
    classification_confidence: float = 1.0

    extracted_iocs: List[IndicatorOfCompromise] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)

    # Sub-Agent Outputs
    triage_report: Optional[Dict[str, Any]] = None
    remediation_plan: Optional[Dict[str, Any]] = None
    code_audit_report: Optional[Dict[str, Any]] = None
    compliance_report: Optional[Dict[str, Any]] = None
    threat_intel_report: Optional[Dict[str, Any]] = None
    executive_summary: Optional[Dict[str, Any]] = None

    # New 12-Agent Architecture Outputs
    ioc_enrichment_report: Optional[Dict[str, Any]] = None
    log_correlation_report: Optional[Dict[str, Any]] = None
    forensics_report: Optional[Dict[str, Any]] = None
    cloud_security_report: Optional[Dict[str, Any]] = None
    network_security_report: Optional[Dict[str, Any]] = None
    risk_report: Optional[Dict[str, Any]] = None

    # Execution trace — append-only, never mutate or delete entries
    execution_trace: List[ExecutionTraceEntry] = Field(default_factory=list)
    current_agent: Optional[str] = None
    status: str = "running"  # running | awaiting_approval | awaiting_clarification | completed | failed
    errors: List[str] = Field(default_factory=list)

    # Clarification flow (low-confidence classification)
    clarification_question: Optional[str] = None
    clarification_answered: bool = False

    # Report artifact paths (populated by Agent 6)
    report_pdf_path: Optional[str] = None
    report_markdown_path: Optional[str] = None
    report_json_path: Optional[str] = None

    def append_trace(self, agent: str, event: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Append an immutable trace entry. Never modify existing entries."""
        self.execution_trace.append(
            ExecutionTraceEntry(
                agent=agent,
                event=event,
                details=details or {},
            )
        )

    def add_error(self, agent: str, message: str) -> None:
        """Add an error message and append to trace."""
        error = f"[{agent}] {message}"
        self.errors.append(error)
        self.append_trace(agent=agent, event="error", details={"message": message})

    @property
    def critical_findings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity == "CRITICAL"]

    @property
    def finding_summary(self) -> Dict[str, int]:
        from collections import Counter
        counts = Counter(f.severity for f in self.findings)
        return {
            "CRITICAL": counts.get("CRITICAL", 0),
            "HIGH": counts.get("HIGH", 0),
            "MEDIUM": counts.get("MEDIUM", 0),
            "LOW": counts.get("LOW", 0),
            "INFORMATIONAL": counts.get("INFORMATIONAL", 0),
            "total": len(self.findings),
        }
