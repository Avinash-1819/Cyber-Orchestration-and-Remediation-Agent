# 🛡️ CORE — Cyber Orchestration & Remediation Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/React-18-cyan.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-emerald.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)

**CORE (Cyber Orchestration and Remediation Engine)** is an enterprise-grade, autonomous **12-agent** cybersecurity platform built on **LangGraph**, **FastAPI**, and **React 18**. It ingests raw security events, source code, Dockerfiles, Terraform/IaC configs, network exposure data, and vulnerability alerts, then orchestrates real-time incident triage, IOC enrichment, log correlation, forensics, automated remediation playbooks, GRC compliance auditing, and threat intelligence — all driven by **deterministic rule-based engines** with optional hosted Gemini LLM narratives. No models are trained on your data.

---

## 🚀 Key Features

- **🤖 12 Specialized Sub-Agents**: Autonomous agents collaborating via a shared `SentinelState` (Pydantic v2) data model.
- **🎛️ Dual Operational Modes**:
  - **Auto Orchestration**: One input box — the Master Orchestrator classifies the payload and routes it through the correct LangGraph pipeline.
  - **Modular Scanner Portal**: 10 specialized scanner views (sidebar dropdown) for targeted single-node or custom pipeline execution.
- **🔀 4 Executable Pipelines + Combo**:
  - **Pipeline A** — Code/IaC audit: DevSecOps → Cloud Security → Compliance → Risk Scoring → Exec Report
  - **Pipeline B** — Incident response: Triage → IOC Enrichment → Log Correlation → Forensics → Remediation → Threat Intel → Risk Scoring → Exec Report
  - **Pipeline C** — Threat intelligence: Threat Intel → Risk Scoring → Exec Report
  - **Pipeline D** — Network exposure: Network Security → Risk Scoring → Exec Report
  - **A_THEN_B** — Mixed input: full Pipeline A, then feeds code-audit context into Pipeline B.
- **🎯 Deterministic Rule Engines**: All 12 agents run offline-first engines (regex/rule based) — results never depend on an API being online.
- **🌐 Real Live Security API Integrations**:
  - **VirusTotal API v3**: Live hash, domain, and IP reputation enrichment.
  - **Shodan REST API**: Host port scans, banners, and geolocation.
  - **NVD REST API 2.0**: CVSS v3.1 vectors and published vulnerability metadata.
  - **MITRE ATT&CK v13 STIX dataset**: Bundled offline (`enterprise-attack.json`, 858 techniques) for technique mapping without an API call.
- **⚡ Grafify Token Minimization**: Graph-based prompt compaction and log deduplication that reduce LLM token usage by **50–80%**.
- **🛡️ Human-in-the-Loop Approval Gates**: Destructive actions (service termination, firewall changes, IAM revokes) require operator authorization.
- **📄 Commercial Multi-Format PDF/MD/JSON Export**: Multi-page ReportLab PDF briefings, Markdown summaries, and raw state JSON — plus per-agent technical PDFs.

---

## 🤖 The 12 Core AI Sub-Agents

```
                            ┌─────────────────────────────┐
                            │    Master Orchestrator      │
                            └─────────────┬───────────────┘
                  ┌───────────────────────┼───────────────────────┐
                  ▼                       ▼                       ▼
         ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
         │  Pipeline A  │        │  Pipeline B  │        │  Pipeline C  │
         │   (DevSecOps)│        │ (Incident)   │        │ (Threat Intel)│
         └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
                │                       │                       │
                ▼                       ▼                       ▼
         ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
         │   Cloud Sec  │        │  IOC Enrich  │        │  Risk Score  │
         └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
                │                       │                       │
                ▼                       ▼                       ▼
         ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
         │  Compliance  │        │Log Correlation│       │ Exec Reporting│
         └──────┬───────┘        └──────┬───────┘        └──────────────┘
                │                       │                       ▲
                └───────────┬───────────┘                       │
                            ▼                                   │
                   ┌──────────────┐        ┌──────────────┐     │
                   │  Risk Score  │        │  Forensics   │     │
                   └──────┬───────┘        └──────┬───────┘     │
                          │                      │             │
                          └──────────┬───────────┘             │
                                     ▼                         │
                            ┌──────────────┐                   │
                            │  Remediation │───────────────────┘
                            └──────────────┘
```

1. **🎯 Master Orchestrator**: Ingests raw inputs, classifies intent (LLM + deterministic fallback), and routes through LangGraph pipelines A / B / C / D / A_THEN_B.
2. **🔍 Incident Triage Agent (`IncidentTriageAgent`)**: Parses logs, extracts IPv4/domain/hash/email IOCs via regex, enriches via VirusTotal & Shodan, classifies TP/FP.
3. **🌐 IOC Enrichment Agent (`IOCEnrichmentAgent`)**: Deep-dives each indicator — hash algorithm/entropy, IP classification, domain TLD risk, external verdicts.
4. **📡 Log Correlation Agent (`LogCorrelationAgent`)**: Correlates events into an attack timeline and identifies kill-chain progression.
5. **🧪 Forensics Agent (`ForensicsAgent`)**: Triages host artifacts (processes, scheduled tasks, autoruns, file hashes) into evidence trails.
6. **⚡ Remediation Agent (`RemediationAgent`)**: Translates findings into OS containment playbooks (`iptables`, `powershell`, `kubectl`, `aws-cli`) with approval gates.
7. **🛡️ DevSecOps Agent (`DevSecOpsAgent`)**: SAST scanning, regex secret detection (with redaction), Dockerfile auditing, and Terraform/IaC checks.
8. **☁️ Cloud Security Agent (`CloudSecurityAgent`)**: Audits cloud infrastructure (AWS/GCP/Azure/Terraform) for misconfigurations.
9. **🌐 Network Security Agent (`NetworkSecurityAgent`)**: Analyzes open ports, firewall rules, and external attack surface.
10. **📋 Compliance Agent (`ComplianceAgent`)**: Maps findings to **ISO 27001**, **SOC 2**, **NIST SP 800-53**, and **PCI DSS 4.0** with 0–100% ratings.
11. **🧠 Threat Intel Agent (`ThreatIntelAgent`)**: NVD CVE CVSS metrics, **MITRE ATT&CK** technique mapping, Sigma and YARA detection rules.
12. **📈 Risk Scoring Agent (`RiskScoringAgent`)**: Aggregates findings into an overall risk score and posture.
13. **📊 Exec Reporting Agent (`ExecReportingAgent`)**: Synthesizes executive briefings and compiles PDF/Markdown/JSON reports.

---

## 🎛️ The 10 Specialized Scanner Modes

| Scanner Mode | Agents Executed | Description |
|---|---|---|
| **⚡ Auto Orchestration** | All 12 (classifier picks pipeline) | Unified auto-classification and routing for mixed payloads. |
| **🛡️ SAST Code Scanner** | `DevSecOpsAgent` | Detects SQLi, XSS, secrets, and insecure patterns in source code. |
| **🐳 Dockerfile Auditor** | `DevSecOpsAgent` + `CloudSecurityAgent` | Detects privileged containers, `latest` tags, and build secrets. |
| **🏗️ Terraform / IaC Analyzer** | `DevSecOpsAgent` + `CloudSecurityAgent` + `ComplianceAgent` | Audits IAM misconfigs, open security groups, and public S3 buckets. |
| **📡 Network Exposure Analyzer** | `NetworkSecurityAgent` + `RiskScoringAgent` + `ExecReportingAgent` | Analyzes open ports, firewall rules, and attack surface. |
| **📊 Incident Triage Engine** | Triage → IOC Enrichment → Log Correlation → Forensics → Remediation | Full incident investigation from raw logs. |
| **🔍 Threat Enricher** | `IncidentTriageAgent` + `IOCEnrichmentAgent` + `ThreatIntelAgent` | Enriches IPs, domains, hashes via VirusTotal, Shodan & MITRE. |
| **📜 GRC Compliance Mapper** | DevSecOps → Cloud Security → Compliance → Exec Report | Maps findings to ISO 27001, SOC 2, NIST, PCI DSS 4.0. |
| **🎯 CVE & ATT&CK Intel** | `ThreatIntelAgent` + `RiskScoringAgent` + `ExecReportingAgent` | Live NVD CVE lookup, MITRE ATT&CK mapping, Sigma/YARA rules. |
| **📄 Executive PDF Report** | Full pipeline + `ExecReportingAgent` | Commercial PDF/Markdown/JSON reports from any input. |

---

## 📦 Quickstart & Installation

### Prerequisites
- [Python 3.11+](https://www.python.org/) (backend)
- [Node.js 20+](https://nodejs.org/) (frontend)
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/) (optional)
- Gemini API Key (optional — deterministic engines run without it)

---

### Option 1: Manual Development Setup (fastest)

#### Backend
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows (PowerShell)
# source .venv/bin/activate    # macOS / Linux
pip install -r requirements.txt
cp ..\.env.example ..\.env      # then edit .env with your API keys
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend
```bash
cd frontend
npm install
npm run dev                     # serves on http://localhost:9090
```

- **Frontend**: [http://localhost:9090](http://localhost:9090)
- **Backend API**: [http://localhost:8000](http://localhost:8000)
- **Swagger API Docs**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)

> The frontend reads the backend URL from `VITE_API_URL` (`frontend/.env`, default `http://localhost:8000/api/v1`). Set it to `http://localhost:9090` if you serve everything behind one origin.

---

### Option 2: Docker Compose

1. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env and insert your GEMINI_API_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY
   ```
2. **Build and launch**:
   ```bash
   docker-compose up --build -d
   ```
3. **Access**:
   - **Frontend**: [http://localhost:5173](http://localhost:5173)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **Swagger API Docs**: [http://localhost:8000/api/docs](http://localhost:8000/api/docs)

---

## ⚙️ Environment Variables (`.env`)

```env
# Application
APP_ENV=development            # development | production
APP_HOST=0.0.0.0
APP_PORT=8000
APP_LOG_LEVEL=INFO
FRONTEND_URL=http://localhost:5173

# JWT Auth — leave JWT_SECRET blank to auto-generate on boot
JWT_SECRET=
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# GitHub OAuth2 (optional)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://localhost:8000/api/v1/auth/github/callback

# Database
DATABASE_URL=sqlite+aiosqlite:///./sentinel.db

# Gemini / Google AI (optional — engines run deterministically without it)
GEMINI_API_KEY=

# LLM model routing
LLM_MODEL_PRO=gemini-2.5-pro
LLM_MODEL_FLASH=gemini-2.0-flash
LLM_MODEL_FLASH_LITE=gemini-2.0-flash-lite

# External Intel APIs (optional)
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
NVD_API_KEY=

# Rate limiting & cache TTLs
RATE_LIMIT_SCAN_PER_MINUTE=10
RATE_LIMIT_GLOBAL_PER_MINUTE=100
IOC_CACHE_TTL_SECONDS=86400
CVE_CACHE_TTL_SECONDS=604800

# Reporting & MITRE data
REPORTS_OUTPUT_DIR=./data/reports
MITRE_DATA_PATH=./data/mitre/enterprise-attack.json

# Local username/password auth (disable in production)
ENABLE_LOCAL_AUTH=true
```

---

## 📑 API Reference Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/local/register` | Register a local user account |
| `POST` | `/api/v1/auth/local/login` | Authenticate and receive a JWT access token |
| `POST` | `/api/v1/scan` | Start a scan session (`mode: auto` / `custom`, `input_type_hint`) |
| `GET` | `/api/v1/sessions` | List scan sessions for the authenticated user |
| `GET` | `/api/v1/sessions/{id}` | Full session state, findings, and sub-agent outputs |
| `GET` | `/api/v1/incidents/{id}/findings` | Structured findings array for a session |
| `GET` | `/api/v1/incidents/{id}/iocs` | Extracted indicators of compromise for a session |
| `POST` | `/api/v1/incidents/remediation/approve` | Approve a remediation command (audit-logged) |
| `GET` | `/api/v1/reports/{id}/{format}` | Download session report (`pdf`, `markdown`, `json`) |
| `GET` | `/api/v1/reports/agent-docs/{agent_id}/pdf` | Per-agent technical PDF documentation |
| `WS` | `/api/v1/ws/{session_id}` | Live WebSocket stream of agent state + execution traces |

---

## 🧪 Testing & Verification

Run the unit test suite (fast, no live calls):

```bash
cd backend
.venv\Scripts\python.exe -m pytest tests/unit -q     # Windows
# .venv/bin/python -m pytest tests/unit -q          # macOS / Linux
```

> ⚠️ The full `tests/` suite includes live end-to-end Gemini calls and may take a long time / rate-limit. Use `tests/unit` for the fast baseline.

---

## 📂 Project Directory Structure

```
cyber-orchestration/
├── docker-compose.yml            # Container orchestration (Backend + Frontend)
├── .env.example                  # Environment variables template
├── README.md                     # This file
│
├── docs/
│   └── agents/                   # Markdown + PDF manuals for all 12 agents
│       ├── 00_master_orchestrator.md
│       ├── 01_incident_triage_agent.md
│       ├── ...                   # 01–12 agent docs
│       └── pdf/                  # Printable ReportLab PDFs (01–12)
│
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI entry point & lifespan
│   │   ├── agents/               # 12 agents + orchestrator + state
│   │   │   ├── orchestrator.py   # Master Orchestrator & LangGraph graph
│   │   │   ├── state.py          # SentinelState Pydantic v2 schema
│   │   │   ├── base_agent.py     # Base agent (tracing, LLM wiring)
│   │   │   ├── triage_agent.py, ioc_enrichment_agent.py, ...
│   │   │   ├── devsecops_agent.py, cloud_security_agent.py, ...
│   │   │   └── exec_reporting_agent.py
│   │   ├── api/v1/endpoints/     # scan, sessions, reports, incidents, auth, ws
│   │   ├── core/                 # Config, security, logging, exceptions
│   │   ├── db/                   # SQLAlchemy models & repositories
│   │   └── services/
│   │       ├── engines/          # 12 deterministic rule engines
│   │       ├── llm_client.py     # Hosted Gemini client (optional)
│   │       ├── report_engine.py  # ReportLab PDF engine
│   │       ├── agent_docs.py     # Per-agent PDF generator
│   │       └── external_intel.py # VirusTotal / Shodan / NVD
│   └── data/
│       ├── mitre/                # MITRE ATT&CK STIX dataset (enterprise-attack.json)
│       ├── compliance_mappings/  # ISO 27001, SOC 2, NIST, PCI DSS datasets
│       ├── agent_docs/pdf/       # Generated agent documentation PDFs
│       └── reports/              # Generated session reports
│
└── frontend/                     # React 18 + TypeScript + Tailwind CSS
    ├── src/
    │   ├── App.tsx               # React Router setup
    │   ├── pages/                # Agent, Sessions, SessionDetail, Scan, ...
    │   ├── services/api.ts       # Axios client + WebSocket helper (VITE_API_URL)
    │   ├── store/auth.ts         # Zustand auth store
    │   └── components/           # CoreLayout sidebar, PipelineTimeline, ...
    ├── vite.config.ts            # Dev server (port 9090)
    ├── Dockerfile
    └── nginx.conf                # SPA Nginx proxy config
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for details.
