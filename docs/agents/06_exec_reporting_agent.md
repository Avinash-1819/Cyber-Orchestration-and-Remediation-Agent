# 📊 Executive Reporting Agent (`ExecReportingAgent`)

## Overview
The **Executive Reporting Agent** acts as the final synthesis node in the CORE pipeline graph. It aggregates state from all upstream agents, computes risk scores, and generates multi-format security reports.

- **Source Code**: [`backend/app/agents/exec_reporting_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/exec_reporting_agent.py)
- **PDF Report Generator Service**: [`backend/app/services/report_engine.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/services/report_engine.py)
- **Model Used**: `gemini-2.0-flash`

---

## 📄 Generated Report Formats

### 1. ReportLab PDF Report (`GET /api/v1/reports/{session_id}/pdf`)
- Commercial-grade multi-page PDF document featuring executive summary, severity pie chart, finding breakdown table, remediation steps, and GRC compliance checklists.

### 2. Markdown Briefing (`GET /api/v1/reports/{session_id}/markdown`)
- GitHub-Flavored Markdown summary suitable for ticketing systems (Jira, GitHub Issues) or SOC logs.

### 3. Machine-Readable JSON (`GET /api/v1/reports/{session_id}/json`)
- Full serialized state JSON matching the `SentinelState` Pydantic v2 schema.

---

## 📊 Risk Level Calculation

Assigns an overall session risk classification:
- **CRITICAL**: If $\ge 1$ Critical finding or active breach detected.
- **HIGH**: If $\ge 1$ High finding or unpatched exploit.
- **MEDIUM**: If Medium severity issues exist.
- **LOW**: Minor issues or hardening recommendations.
