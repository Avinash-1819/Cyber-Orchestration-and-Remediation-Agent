# 🎯 Master Orchestrator Agent (`MasterOrchestrator`)

## Overview
The **Master Orchestrator** is the core entry point of the CORE LangGraph state machine. It analyzes raw incoming security payloads, determines the primary data type, evaluates classification confidence, and routes execution to the appropriate pipeline.

- **Source Code**: [`backend/app/agents/orchestrator.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/orchestrator.py)
- **Model Used**: `gemini-3.5-flash-lite` (Fast, low-latency intent classification)

---

## ⚙️ Operational Pipelines

```
                   Input Payload
                         │
                         ▼
             [Payload Classification]
                         │
       ┌─────────────────┼─────────────────┬─────────────────┐
       ▼                 ▼                 ▼                 ▼
  Pipeline A        Pipeline B        Pipeline C      Pipeline A_THEN_B
   (DevSecOps)       (Triage)       (Threat Intel)        (Mixed)
```

1. **Pipeline A (Code / IaC)**: `DevSecOpsAgent` → `ComplianceAgent` → `ExecReportingAgent`
2. **Pipeline B (Logs / IOCs)**: `IncidentTriageAgent` → `RemediationAgent` → `ThreatIntelAgent` → `ExecReportingAgent`
3. **Pipeline C (CVE / TTP / Query)**: `ThreatIntelAgent` → `ExecReportingAgent`
4. **Pipeline A_THEN_B (Mixed Inputs)**: Executes Pipeline A followed by Pipeline B with shared state.
5. **Custom Pipeline**: Executes only the specific agents requested by the user.

---

## 📊 Classification Schema

```python
class PayloadClassification(BaseModel):
    input_type: str  # CODE | LOGS | REPO_URL | CVE | IOC | MIXED | QUERY
    pipeline: str    # A | B | C | A_THEN_B | CUSTOM
    confidence: float  # 0.0 to 1.0
    reasoning: str
    clarification_question: Optional[str] = None
```

---

## 🔍 Features & Guardrails

- **Low Confidence Threshold (`0.60`)**: If classification confidence falls below 0.60, the orchestrator sets `status = "awaiting_clarification"` and returns a question without executing blind pipelines.
- **Natural Language Support (`QUERY`)**: Short questions like `"hi"`, `"explain SQL injection"` route to Pipeline C for direct conversational responses.
- **Grafify Token Minimization**: Caches compiled graph singletons (`_compiled_graph`) for zero overhead re-use across async execution contexts.
