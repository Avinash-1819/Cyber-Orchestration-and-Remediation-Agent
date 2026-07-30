# 🛡️ CORE Multi-Agent Platform — Documentation Index

Welcome to the comprehensive technical documentation for the **Cyber Orchestration and Remediation Engine (CORE)** multi-agent system.

CORE utilizes a stateful **LangGraph** orchestration graph that routes cybersecurity payloads through specialized autonomous AI agents.

---

## 📚 Agent Documentation Modules

| # | Agent Name | File Link | Core Responsibilities |
|---|---|---|---|
| 0 | **Master Orchestrator** | [00_master_orchestrator.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/00_master_orchestrator.md) | Intent classification, low-confidence handling, state routing |
| 1 | **Incident Triage Agent** | [01_incident_triage_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/01_incident_triage_agent.md) | Log parsing, IOC extraction, VirusTotal v3 & Shodan REST enrichment |
| 2 | **Remediation Agent** | [02_remediation_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/02_remediation_agent.md) | Playbook generation, systemd/iptables/kubectl containment, destructive action gates |
| 3 | **DevSecOps Agent** | [03_devsecops_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/03_devsecops_agent.md) | SAST scanning, regex secret detection, Dockerfile & Terraform audits |
| 4 | **Compliance Agent** | [04_compliance_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/04_compliance_agent.md) | GRC framework mapping (ISO 27001, SOC 2, NIST SP 800-53, PCI DSS 4.0) |
| 5 | **Threat Intel Agent** | [05_threat_intel_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/05_threat_intel_agent.md) | NVD REST 2.0 CVE lookup, MITRE ATT&CK mapping, Sigma & YARA rule generation |
| 6 | **Exec Reporting Agent** | [06_exec_reporting_agent.md](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/docs/agents/06_exec_reporting_agent.md) | Executive briefing synthesis, ReportLab PDF generation, Markdown & JSON export |

---

## 🔄 Graph Architecture

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
