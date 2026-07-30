# 🛡️ CORE — Cyber Orchestration & Remediation Engine

[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![React 18](https://img.shields.io/badge/React-18-cyan.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-emerald.svg)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)

**CORE (Cyber Orchestration and Remediation Engine)** is an enterprise-grade, autonomous multi-agent AI security platform. Built on **LangGraph**, **FastAPI**, and **React 18**, CORE ingests raw security events, source code, Dockerfiles, Terraform configs, and vulnerability alerts to orchestrate real-time incident triage, automated remediation playbooks, GRC compliance auditing, and threat intelligence enrichment.

---

## 🚀 Key Features

- **🤖 6 Specialized Sub-Agents**: Autonomous AI agents working collaboratively via a shared `SentinelState` Pydantic v2 data model.
- **🎛️ Dual Operational Modes**:
  - **Auto Orchestration**: Single input box where the Master Orchestrator automatically classifies payloads and routes execution through LangGraph pipelines.
  - **Modular Scanner Portal**: 8 specialized scanner views accessible via sidebar dropdown for targeted single-node or custom pipeline execution.
- **🌐 Real Live Security API Integrations**:
  - **VirusTotal API v3**: Live file hash, domain, and IP threat reputation enrichment.
  - **Shodan REST API**: Host open port scans, banner grabs, and ISP geolocation.
  - **NVD REST API 2.0**: CVSS v3.1 vector extraction and published vulnerability metadata.
- **⚡ Grafify Token Minimization**: Graph-based prompt compaction and log deduplication routines that reduce input token utilization by **50% to 80%**.
- **🛡️ Human-in-the-Loop Approval Gates**: Destructive system actions (service termination, firewall modifications, IAM revokes) require operator authorization (`APPROVE`).
- **📄 Commercial Multi-Format PDF/MD/JSON Export**: Generates multi-page ReportLab PDF briefings, Markdown summaries, and raw state JSON.

---

## 🤖 The 6 Core AI Sub-Agents

```
                          ┌───────────────────────────┐
                          │    Master Orchestrator    │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  ┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
  │  DevSecOps Agent│          │  Triage Agent   │          │  Threat Intel   │
  └────────┬────────┘          └────────┬────────┘          └────────┬────────┘
           │                            │                            │
           ▼                            ▼                            │
  ┌─────────────────┐          ┌─────────────────┐                   │
  │Compliance Agent │          │Remediation Agent│                   │
  └────────┬────────┘          └────────┬────────┘                   │
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        ▼
                          ┌───────────────────────────┐
                          │ Exec Reporting Agent (PDF)│
                          └───────────────────────────┘
```

1. **🎯 Master Orchestrator (`MasterOrchestrator`)**: Ingests raw inputs, classifies intent using `gemini-3.5-flash-lite`, handles low-confidence cases, and routes execution.
2. **🔍 Incident Triage Agent (`IncidentTriageAgent`)**: Parses logs, extracts IPv4/domain/hash IOCs via regex, and enriches indicators via VirusTotal & Shodan.
3. **⚡ Remediation Agent (`RemediationAgent`)**: Translates triage findings into OS containment playbooks (`iptables`, `powershell`, `kubectl`, `aws-cli`) with safety gates.
4. **🛡️ DevSecOps Agent (`DevSecOpsAgent`)**: Performs SAST scanning, regex secret detection (with automatic redaction), Dockerfile auditing, and Terraform IaC checks.
5. **📋 Compliance Agent (`ComplianceAgent`)**: Maps findings to **ISO 27001**, **SOC 2**, **NIST SP 800-53**, and **PCI DSS 4.0**, calculating quantitative compliance ratings (0–100%).
6. **🧠 Threat Intelligence Agent (`ThreatIntelAgent`)**: Queries NVD CVE CVSS metrics, maps tactics to **MITRE ATT&CK**, and generates production **Sigma** and **YARA** detection rules.
7. **📊 Executive Reporting Agent (`ExecReportingAgent`)**: Synthesizes session risk scores (CRITICAL, HIGH, MEDIUM, LOW) and compiles multi-page ReportLab PDF reports.

---

## 🎛️ The 8 Specialized Scanner Modes

| Scanner Mode | Primary Agents | Description |
|---|---|---|
| **⚡ Auto Orchestration** | Master Orchestrator → All Agents | Unified auto-classification and routing for mixed payloads. |
| **🛡️ SAST Code Scanner** | `DevSecOpsAgent` | Detects SQLi, XSS, secrets, and insecure patterns in code. |
| **🐳 Dockerfile Auditor** | `DevSecOpsAgent` | Detects privileged root containers, latest tags, and build secrets. |
| **🏗️ Terraform / IaC Analyzer** | `DevSecOpsAgent` + `ComplianceAgent` | Audits IAM misconfigurations, open security groups (`0.0.0.0/0`), & public S3 buckets. |
| **📊 Incident Triage Engine** | `TriageAgent` + `RemediationAgent` | Parses logs, enriches IOCs, and generates mitigation playbooks. |
| **🔍 Threat Enricher** | `TriageAgent` + `ThreatIntelAgent` | Enriches IPs, domains, and hashes via live VirusTotal & Shodan lookup. |
| **📜 GRC Compliance Mapper** | `ComplianceAgent` + `ExecReport` | Maps infrastructure vulnerabilities to ISO 27001, SOC 2, NIST, and PCI DSS 4.0. |
| **🎯 CVE & ATT&CK Intel** | `ThreatIntelAgent` | Live NVD CVE lookup, MITRE ATT&CK mapping, and Sigma/YARA generation. |
| **📄 Executive PDF Report** | `ExecReportingAgent` | Produces commercial PDF briefings and Markdown summaries from raw state. |

---

## 📦 Quickstart & Installation

### Prerequisites
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)
- [Python 3.11+](https://www.python.org/) (for local development)
- [Node.js 20+](https://nodejs.org/) (for frontend development)
- Gemini API Key

---

### Option 1: Docker (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/cyber-orchestration.git
   cd cyber-orchestration
   ```

2. **Configure Environment Variables**:
   ```bash
   cp .env.example .env
   # Edit .env and insert your GEMINI_API_KEY, VIRUSTOTAL_API_KEY, SHODAN_API_KEY
   ```

3. **Build and Launch Containers**:
   ```bash
   docker-compose up --build -d
   ```

4. **Access Applications**:
   - **Frontend Interface**: [http://localhost:5173](http://localhost:5173)
   - **Backend API**: [http://localhost:8000](http://localhost:8000)
   - **Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Option 2: Manual Development Setup

#### Backend Setup
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## ⚙️ Environment Variables Configuration (`.env`)

```env
# Application Settings
PROJECT_NAME="Cyber Orchestration and Remediation Engine (CORE)"
ENVIRONMENT="production"

# Security & JWT
JWT_SECRET="super-secret-jwt-key-replace-in-production"
JWT_ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=600

# LLM & External Security API Keys
GEMINI_API_KEY="your-google-gemini-api-key"
VIRUSTOTAL_API_KEY="your-virustotal-api-key"
SHODAN_API_KEY="your-shodan-api-key"

# Database
DATABASE_URL="sqlite+aiosqlite:///./sentinel.db"
```

---

## 📑 API Reference Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/local/register` | Register a local user account |
| `POST` | `/api/v1/auth/local/login` | Authenticate user and receive JWT access token |
| `POST` | `/api/v1/scan` | Initiate a scan session (supports `auto` and `custom` mode) |
| `GET` | `/api/v1/sessions` | List all historical scan sessions for authenticated user |
| `GET` | `/api/v1/sessions/{id}` | Get detailed state, findings, and sub-agent outputs for a session |
| `GET` | `/api/v1/incidents/{id}/findings` | Retrieve structured findings array for a session |
| `GET` | `/api/v1/reports/{id}/{format}` | Download session report artifact (`pdf`, `markdown`, `json`) |
| `GET` | `/api/v1/reports/agent-docs/{agent_id}/pdf` | Download separate technical PDF documentation for a sub-agent |
| `WS` | `/api/v1/ws/{session_id}` | Live WebSocket stream for agent state updates and execution traces |

---

## 🧪 Testing & Verification Suite

Execute the automated test suite verifying all 8 scanners against live payloads:

```bash
cd backend
PYTHONPATH=. .venv/bin/python tests/test_all_8_scanners.py
```

---

## 📂 Project Directory Structure

```
cyber-orchestration/
├── docker-compose.yml          # Container orchestration (Backend + Frontend)
├── .env.example                # Example environment variables template
├── README.md                   # Primary GitHub repository documentation
│
├── docs/                       # Comprehensive documentation modules
│   └── agents/                 # Individual Markdown & PDF manuals for each sub-agent
│       ├── README.md           # Master Documentation Index
│       ├── 00_master_orchestrator.md
│       ├── 01_incident_triage_agent.md
│       ├── 02_remediation_agent.md
│       ├── 03_devsecops_agent.md
│       ├── 04_compliance_agent.md
│       ├── 05_threat_intel_agent.md
│       ├── 06_exec_reporting_agent.md
│       └── pdf/                # Printable ReportLab PDF documentation files
│
├── backend/                    # FastAPI + LangGraph Multi-Agent Engine
│   ├── app/
│   │   ├── main.py             # FastAPI entry point & CORS configuration
│   │   ├── agents/             # The 6 Autonomous AI Agent implementations
│   │   │   ├── orchestrator.py # Master Orchestrator & LangGraph Graph Definition
│   │   │   ├── state.py        # Centralized SentinelState Pydantic v2 Schema
│   │   │   ├── triage_agent.py
│   │   │   ├── remediation_agent.py
│   │   │   ├── devsecops_agent.py
│   │   │   ├── compliance_agent.py
│   │   │   ├── threat_intel_agent.py
│   │   │   └── exec_reporting_agent.py
│   │   ├── api/v1/endpoints/   # REST API routes (scan, sessions, reports, auth)
│   │   ├── core/               # App configuration, security, & rate limiting
│   │   ├── db/                 # Database models & repositories (SQLAlchemy)
│   │   └── services/           # Gemini client, external APIs, ReportLab PDF engine, Grafify
│   └── data/
│       ├── compliance_mappings/# ISO 27001, SOC 2, NIST, PCI DSS YAML datasets
│       └── mitre/              # Local MITRE ATT&CK STIX dataset
│
└── frontend/                   # React 18 + TypeScript + Tailwind CSS UI
    ├── src/
    │   ├── App.tsx             # React Router setup
    │   ├── pages/
    │   │   ├── Agent.tsx       # Primary dual-mode AI Chat & Scanner interface
    │   │   ├── Sessions.tsx    # Session history view
    │   │   └── SessionDetail.tsx # Detailed finding breakdown & state raw view
    │   └── components/
    │       └── layout/
    │           └── CoreLayout.tsx # Sidebar with Scanner Select & Agent Toggles
    ├── Dockerfile
    └── nginx.conf              # SPA Nginx proxy configuration
```

---

## 📜 License

Distributed under the **MIT License**. See `LICENSE` for more details.
