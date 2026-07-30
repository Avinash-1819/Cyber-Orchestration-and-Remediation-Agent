# Sentinel AI — Architectural Decisions Log
# This file records every ambiguous-spec judgment call made during the build.
# It is a living document — updated as decisions are made.

## Decision Log

---

### D-001: Model Names (Spec Correction)
**Spec says:** `gemini-3.5-flash`, `gemini-3.5-flash-lite`
**Decision:** These model names do not exist in the Gemini API. Using:
- `gemini-2.5-pro` (Agents 4 & 6) — correct as specified
- `gemini-2.0-flash` (Agents 1, 2, 3, 5) — actual equivalent of "3.5-flash"
- `gemini-2.0-flash-lite` (Orchestrator classification) — actual equivalent of "3.5-flash-lite"
All model names are configurable via `.env` (LLM_MODEL_PRO, LLM_MODEL_FLASH, LLM_MODEL_FLASH_LITE).

---

### D-002: MITRE ATT&CK Dataset Handling
**Spec says:** Bundle/download the official `enterprise-attack.json` at build/refresh time.
**Decision:** Dataset is ~250MB uncompressed. Implementation:
- `data/mitre/refresh_mitre.py` downloads from MITRE's GitHub at Docker build time
- Falls back gracefully if download fails (e.g. offline build) — agents continue without MITRE context
- Local query via Python STIX2 / JSON indexing, no live API calls during agent execution
- Weekly refresh recommended via cron job (not implemented in v1 — noted for v2)

---

### D-003: Mixed-Input Pipeline (A_THEN_B)
**Spec says:** "Run Pipeline A first, then feed its findings as additional context into Pipeline B's Triage Agent"
**Decision:** Implemented as follows:
1. Full Pipeline A runs (DevSecOps → Compliance)
2. A's `code_audit_report` summary is appended to `raw_input` as bracketed context
3. Triage Agent sees augmented input and generates its own analysis informed by code findings
4. Full Pipeline B runs on top of that
5. Agent 6 synthesizes all upstream outputs
This ensures neither source (code scan nor incident data) is silently dropped.

---

### D-005: Low-Confidence Classification Handling
**Spec says:** "return a clarifying question to the user via the chat UI"
**Decision:** Implemented as a state machine transition to `awaiting_clarification` status:
- Threshold: 0.6 (configurable via `CLASSIFICATION_CONFIDENCE_THRESHOLD` in `.env`)
- API returns `status: "awaiting_clarification"` with `clarification_question` in the ScanResponse
- WebSocket broadcasts `{type: "needs_clarification", question}` to the frontend
- Frontend renders a question in the Scan page for the user to answer
- **Not yet implemented:** user response re-triggering classification (v1 limitation). User must start a new scan with an explicit `input_type_hint`.

---

### D-006: LangGraph Async Integration
**Spec says:** Use LangGraph for the state machine.
**Decision:** LangGraph's native sync invoke is used inside `run_in_executor` to avoid blocking the event loop. This is the correct pattern for LangGraph 0.2.x with async FastAPI. Individual agent `execute()` methods are native asyncio. If LangGraph releases a mature async graph API, this executor pattern should be replaced.

---

### D-007: No Redis in v1
**Spec says:** "SQLite is enough, no separate Redis required for v1 unless you judge the queueing needs otherwise"
**Decision:** Confirmed — no Redis. Rate limiting is in-process (sliding window in memory). Cache is SQLite. WebSocket event broadcasting is per-process asyncio Queue. For multi-worker deployments, Redis would be required for WS fanout and cross-process rate limiting — this is noted as a v2 requirement.

---

### D-008: Remediation Hard Boundary Architecture
**Spec says:** "the backend never auto-executes any remediation command; it only ever generates text/scripts for a human to run. Make this a hard architectural boundary, not just a UI nicety."
**Decision:** Implemented as follows:
- `RemediationAgent` returns only `Dict[str, Any]` — never calls subprocess, os.system, or any execution API
- The `POST /incidents/remediation/approve` endpoint explicitly logs the approval to the audit trail and returns the command text for the user to copy and run manually
- No execution API exists anywhere in the codebase
- The `destructive: true` flag on findings triggers a client-side modal that requires typing "APPROVE" before the copy button activates

---

### D-009: Secret Redaction Implementation
**Spec says:** "Secret-detection regex/entropy results are redacted everywhere"
**Decision:** The `_redact_secret()` function in `devsecops_agent.py` redacts before ANY storage or transmission:
1. Raw secret is never assigned to any variable after redaction
2. The `Finding` object stores only the masked form: `sk-live-****1234`
3. Since `Finding` flows into `SentinelState` which flows into DB, WebSocket, and reports, the redaction propagates everywhere automatically
4. Full entropy-based detection (Shannon entropy calculation) deferred to v2 — regex patterns cover the most common real-world cases

---

### D-010: Auth Strategy
**Spec says:** GitHub OAuth2 + JWT.
**Decision:** Both GitHub OAuth2 and a local dev bypass (ENABLE_LOCAL_AUTH=true) are shipped:
- GitHub OAuth2 is the production path
- Local bypass avoids requiring OAuth app registration for local development
- Local auth is rejected at the endpoint level when ENABLE_LOCAL_AUTH=false
- JWT is HS256, auto-generated secret at first boot if not configured

---

### D-011: Session Persistence Strategy
**Spec says:** "Sessions are resumable — a user can reopen a past investigation and see the full execution trace"
**Decision:** Full `SentinelState` is serialized as JSON and stored in `scan_sessions.state_json`. The `GET /sessions/{id}` endpoint returns this full state, allowing the frontend to reconstruct the entire execution trace and all agent outputs. The denormalized fields (finding_count, critical_count, etc.) avoid deserializing the full state for list views.

---

### D-012: Report Generation Strategy
**Spec says:** PDF, Markdown, and JSON derived from same SentinelState object.
**Decision:** `report_engine.py` generates all three from `SentinelState.model_dump()` / the same state object in a single `generate_all_reports()` call. Files are stored at `data/reports/{session_id}/report.{pdf|md|json}`. Download served via `GET /reports/{session_id}/{format}` as FileResponse.

---

### D-013: Frontend Technology
**Spec says:** React 18, Vite, TypeScript, Tailwind CSS, Lucide Icons, TanStack Query, native WebSocket client.
**Decision:** All specified. Added:
- `framer-motion` for page transitions and animation (spec requires "micro-animations")
- `recharts` for data visualization
- `react-router-dom` v6 for client-side routing
- `localStorage` for JWT token persistence (HttpOnly cookie would be more secure but requires server-side session management)

---

### D-014: Compliance Mapping Seed Files
**Spec says:** "Ship the control-mapping table as a versioned, human-editable JSON/YAML seed file"
**Decision:** Four separate YAML files in `backend/data/compliance_mappings/`:
- `iso27001.yaml` (ISO 27001:2022)
- `nist_800_53.yaml` (NIST SP 800-53 Rev 5)
- `soc2.yaml` (SOC 2 Type II Trust Services Criteria)
- `pci_dss_4.yaml` (PCI DSS 4.0)
Each file has a version field for auditor reference. The LLM loads these via `yaml.safe_load()` and applies them — it does NOT generate control IDs from memory.
