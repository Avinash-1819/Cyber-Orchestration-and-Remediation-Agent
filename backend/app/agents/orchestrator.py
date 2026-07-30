"""
Sentinel AI — Master Orchestrator (LangGraph State Machine)
Classifies payload → routes to one of 3 pipelines → always ends with Agent 6.

Pipelines:
  A: CODE/REPO/IaC  → DevSecOps → Compliance → Exec Report
  B: LOGS/IOC       → Triage    → Remediation → Threat Intel → Exec Report
  C: CVE/TTP        → Threat Intel → Exec Report
  A_THEN_B: Mixed   → (Full Pipeline A) then (Pipeline B with A's findings as context)

Classification uses gemini-flash-lite (cheap, fast).
Low-confidence (<0.6 threshold) → returns NEEDS_CLARIFICATION, does not route blind.
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Literal, Optional

import structlog
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from app.agents.base_agent import _broadcast_state_update
from app.agents.compliance_agent import ComplianceAgent
from app.agents.devsecops_agent import DevSecOpsAgent
from app.agents.exec_reporting_agent import ExecReportingAgent
from app.agents.remediation_agent import RemediationAgent
from app.agents.state import SentinelState
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.agents.triage_agent import TriageAgent
from app.core.config import settings
from app.core.exceptions import ClassificationError, LowConfidenceError
from app.services.llm_client import MODEL_FLASH_LITE, get_llm_client

log = structlog.get_logger(__name__)

# ============================================================
# Classification Schema
# ============================================================

class PayloadClassification(BaseModel):
    input_type: str = Field(
        description="One of: CODE, LOGS, REPO_URL, CVE, IOC, MIXED"
    )
    pipeline: str = Field(
        description="One of: A, B, C, A_THEN_B"
    )
    confidence: float = Field(
        description="0.0 to 1.0 classification confidence"
    )
    reasoning: str = Field(
        description="Brief explanation of why this pipeline was chosen"
    )
    clarification_question: Optional[str] = Field(
        default=None,
        description="If confidence < 0.6, provide a clarifying question for the user"
    )


# ============================================================
# Agent instances (singletons reused across requests)
# ============================================================

_triage_agent = TriageAgent()
_remediation_agent = RemediationAgent()
_devsecops_agent = DevSecOpsAgent()
_compliance_agent = ComplianceAgent()
_threat_intel_agent = ThreatIntelAgent()
_exec_reporting_agent = ExecReportingAgent()


# ============================================================
# Classification Node
# ============================================================

async def classify_payload(state: SentinelState) -> SentinelState:
    """
    Classify the input payload using gemini-flash-lite.
    Handles mixed inputs and low-confidence cases.
    """
    llm = get_llm_client()

    prompt = f"""Classify this cybersecurity input to determine which analysis pipeline to use.

INPUT (first 2000 chars):
{state.raw_input[:2000]}

PIPELINE DECISION RULES:
- Pipeline A: Use for source code files (.py/.js/.java/.go etc), GitHub repository URLs (https://github.com/...), Dockerfiles, Terraform (.tf), CI/CD YAML, IaC configs
- Pipeline B: Use for firewall/IDS/IPS logs, syslog, Windows Event Logs, network packet data, IP addresses, file hashes, domains as IOCs in an incident context
- Pipeline C: Use for CVE IDs (CVE-YYYY-NNNN format), malware family names, explicit threat hunt requests, MITRE technique IDs
- Pipeline A_THEN_B: Use when input CLEARLY contains BOTH source code/repo AND active incident IOCs together
- INPUT_TYPE: CODE (source code), LOGS (log files/syslog), REPO_URL (GitHub URL), CVE (CVE identifiers), IOC (indicators in incident context), MIXED (multiple types), QUERY (natural language security question or short question)
- IMPORTANT: Short natural language questions like 'hello', 'what can you do', 'explain X', or general security questions → Pipeline C, INPUT_TYPE=QUERY, confidence=0.95

If confidence < 0.6, set clarification_question to ask the user which type of analysis they want."""

    try:
        classification = await llm.generate_structured(
            prompt=prompt,
            output_schema=PayloadClassification,
            model_role=MODEL_FLASH_LITE,
            agent_name="MasterOrchestrator",
            temperature=0.0,
        )

        state.input_type = classification.input_type
        state.pipeline = classification.pipeline
        state.classification_confidence = classification.confidence

        state.append_trace(
            agent="MasterOrchestrator",
            event="classified",
            details={
                "input_type": classification.input_type,
                "pipeline": classification.pipeline,
                "confidence": classification.confidence,
                "reasoning": classification.reasoning,
            },
        )

        await _broadcast_state_update(state.session_id, {
            "type": "classified",
            "input_type": classification.input_type,
            "pipeline": classification.pipeline,
            "confidence": classification.confidence,
            "session_id": state.session_id,
        })

        # Handle low-confidence case
        if classification.confidence < settings.CLASSIFICATION_CONFIDENCE_THRESHOLD:
            state.status = "awaiting_clarification"
            state.clarification_question = (
                classification.clarification_question or
                "I couldn't determine the type of input with confidence. "
                "Could you tell me: is this (A) source code/repository, (B) security logs/incident data, or (C) CVE/vulnerability information?"
            )
            log.warning(
                "classification_low_confidence",
                confidence=classification.confidence,
                threshold=settings.CLASSIFICATION_CONFIDENCE_THRESHOLD,
            )
            await _broadcast_state_update(state.session_id, {
                "type": "needs_clarification",
                "question": state.clarification_question,
                "session_id": state.session_id,
            })

        log.info(
            "payload_classified",
            session_id=state.session_id,
            input_type=classification.input_type,
            pipeline=classification.pipeline,
            confidence=classification.confidence,
        )

    except Exception as e:
        log.error("classification_error", error=str(e), session_id=state.session_id)
        # Default to Pipeline B (most common) on classification failure
        state.pipeline = "B"
        state.input_type = "LOGS"
        state.classification_confidence = 0.0
        state.add_error("MasterOrchestrator", f"Classification failed, defaulting to Pipeline B: {e}")

    return state


# ============================================================
# Pipeline routing condition
# ============================================================

def route_pipeline(state: SentinelState) -> str:
    """Determine next node based on pipeline classification."""
    if state.status == "awaiting_clarification":
        return "needs_clarification"
    if state.pipeline == "A":
        return "pipeline_a"
    elif state.pipeline == "B":
        return "pipeline_b"
    elif state.pipeline == "C":
        return "pipeline_c"
    elif state.pipeline == "A_THEN_B":
        return "pipeline_a_then_b"
    else:
        return "pipeline_b"  # Safe default


# ============================================================
# Pipeline execution nodes (wrap agents for LangGraph)
# ============================================================

async def run_pipeline_a(state: SentinelState) -> SentinelState:
    """Pipeline A: DevSecOps → Compliance → ExecReport"""
    state = await _devsecops_agent.run(state)
    state = await _compliance_agent.run(state)
    state = await _exec_reporting_agent.run(state)
    return state


async def run_pipeline_b(state: SentinelState) -> SentinelState:
    """Pipeline B: Triage → Remediation → ThreatIntel → ExecReport"""
    state = await _triage_agent.run(state)
    state = await _remediation_agent.run(state)
    state = await _threat_intel_agent.run(state)
    state = await _exec_reporting_agent.run(state)
    return state


async def run_pipeline_c(state: SentinelState) -> SentinelState:
    """Pipeline C: ThreatIntel → ExecReport"""
    state = await _threat_intel_agent.run(state)
    state = await _exec_reporting_agent.run(state)
    return state


async def run_pipeline_a_then_b(state: SentinelState) -> SentinelState:
    """
    Pipeline A_THEN_B: Mixed input with both code and active IOCs.
    Runs full Pipeline A first, then feeds findings as context into Pipeline B.
    """
    state.append_trace(
        agent="MasterOrchestrator",
        event="mixed_pipeline_start",
        details={"order": "A → B", "reason": "Mixed input detected: code/repo AND active IOCs"},
    )
    # Run Pipeline A
    state = await _devsecops_agent.run(state)
    state = await _compliance_agent.run(state)

    # Feed A's code audit findings as additional context for Pipeline B's triage
    if state.code_audit_report:
        existing_input = state.raw_input
        a_context = (
            f"\n\n[ADDITIONAL CONTEXT FROM CODE SCAN]\n"
            f"Code Audit Risk: {state.code_audit_report.get('overall_risk_level')}\n"
            f"Summary: {state.code_audit_report.get('summary', '')[:500]}\n"
        )
        # Temporarily augment raw_input for triage context (restore after)
        state.raw_input = existing_input + a_context

    # Run Pipeline B
    state = await _triage_agent.run(state)
    state = await _remediation_agent.run(state)
    state = await _threat_intel_agent.run(state)

    # Final exec report with full combined state
    state = await _exec_reporting_agent.run(state)
    return state


async def handle_needs_clarification(state: SentinelState) -> SentinelState:
    """Terminal node for low-confidence classification — returns state to caller."""
    log.info("returning_clarification_question", session_id=state.session_id)
    # Status is already set to awaiting_clarification — the API will return this to the client
    return state


# ============================================================
# Build the LangGraph graph
# ============================================================

def build_graph() -> StateGraph:
    """Build and compile the Sentinel AI LangGraph state machine."""
    # We use a dict-based state since LangGraph works with TypedDict/Annotated,
    # but we serialize/deserialize SentinelState at the boundary
    from typing import TypedDict

    class GraphState(TypedDict):
        sentinel_state: dict  # serialized SentinelState

    graph = StateGraph(GraphState)

    # Node wrappers that serialize/deserialize SentinelState
    async def _wrap(fn, state_dict: GraphState) -> GraphState:
        s = SentinelState.model_validate(state_dict["sentinel_state"])
        s = await fn(s)
        return {"sentinel_state": s.model_dump(mode="json")}

    async def node_classify(s): return await _wrap(classify_payload, s)
    async def node_pipeline_a(s): return await _wrap(run_pipeline_a, s)
    async def node_pipeline_b(s): return await _wrap(run_pipeline_b, s)
    async def node_pipeline_c(s): return await _wrap(run_pipeline_c, s)
    async def node_pipeline_a_then_b(s): return await _wrap(run_pipeline_a_then_b, s)
    async def node_needs_clarification(s): return await _wrap(handle_needs_clarification, s)

    graph.add_node("classify", node_classify)
    graph.add_node("pipeline_a", node_pipeline_a)
    graph.add_node("pipeline_b", node_pipeline_b)
    graph.add_node("pipeline_c", node_pipeline_c)
    graph.add_node("pipeline_a_then_b", node_pipeline_a_then_b)
    graph.add_node("needs_clarification", node_needs_clarification)

    graph.set_entry_point("classify")

    def _route(state_dict: GraphState) -> str:
        s = SentinelState.model_validate(state_dict["sentinel_state"])
        return route_pipeline(s)

    graph.add_conditional_edges(
        "classify",
        _route,
        {
            "pipeline_a": "pipeline_a",
            "pipeline_b": "pipeline_b",
            "pipeline_c": "pipeline_c",
            "pipeline_a_then_b": "pipeline_a_then_b",
            "needs_clarification": "needs_clarification",
        },
    )

    for node in ["pipeline_a", "pipeline_b", "pipeline_c", "pipeline_a_then_b", "needs_clarification"]:
        graph.add_edge(node, END)

    return graph.compile()


# ============================================================
# Public API used by the scan endpoint
# ============================================================

_compiled_graph = None


def get_compiled_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


# Agent name → runner mapping
_AGENT_MAP = {
    "IncidentTriageAgent": lambda s: _triage_agent.run(s),
    "RemediationAgent": lambda s: _remediation_agent.run(s),
    "DevSecOpsAgent": lambda s: _devsecops_agent.run(s),
    "ComplianceAgent": lambda s: _compliance_agent.run(s),
    "ThreatIntelAgent": lambda s: _threat_intel_agent.run(s),
    "ExecReportingAgent": lambda s: _exec_reporting_agent.run(s),
}


async def run_pipeline(
    state: SentinelState,
    selected_agents: list[str] | None = None,
    mode: str = "auto",
) -> SentinelState:
    """
    Run the CORE pipeline.
    - mode='auto': full LangGraph orchestration (classify → route → agents → report)
    - mode='custom': run only the agents listed in selected_agents, then ExecReportingAgent
    """
    state.append_trace(
        agent="MasterOrchestrator",
        event="pipeline_start",
        details={"session_id": state.session_id, "user_id": state.user_id, "mode": mode},
    )

    # Custom mode: bypass classifier, run only selected agents
    if mode == "custom" and selected_agents:
        valid = [a for a in selected_agents if a in _AGENT_MAP]
        # Always append ExecReportingAgent at end if not already there
        if "ExecReportingAgent" not in valid:
            valid.append("ExecReportingAgent")
        state.pipeline = "CUSTOM"
        state.input_type = state.input_type or "UNKNOWN"
        await _broadcast_state_update(state.session_id, {
            "type": "classified",
            "input_type": state.input_type,
            "pipeline": "CUSTOM",
            "confidence": 1.0,
            "session_id": state.session_id,
        })
        try:
            for agent_name in valid:
                runner = _AGENT_MAP[agent_name]
                state = await runner(state)
            state.status = "completed"
        except Exception as e:
            log.exception("custom_pipeline_error", session_id=state.session_id)
            state.status = "failed"
            state.add_error("MasterOrchestrator", f"Custom pipeline failed: {e}")
        return state

    # Auto mode: full LangGraph graph
    graph = get_compiled_graph()
    try:
        result = await graph.ainvoke({"sentinel_state": state.model_dump(mode="json")})
        final_state = SentinelState.model_validate(result["sentinel_state"])
        return final_state

    except Exception as e:
        log.exception("pipeline_error", session_id=state.session_id)
        state.status = "failed"
        state.add_error("MasterOrchestrator", f"Pipeline execution failed: {e}")
        return state
