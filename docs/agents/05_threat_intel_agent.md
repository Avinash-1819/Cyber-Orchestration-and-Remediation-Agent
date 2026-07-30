# 🧠 Threat Intelligence Agent (`ThreatIntelAgent`)

## Overview
The **Threat Intelligence Agent** processes CVE IDs, vulnerability descriptions, and threat indicators. It queries vulnerability databases, maps techniques to MITRE ATT&CK, and generates automated detection signatures.

- **Source Code**: [`backend/app/agents/threat_intel_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/threat_intel_agent.py)
- **MITRE Dataset Manager**: [`backend/data/mitre/refresh_mitre.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/data/mitre/refresh_mitre.py)
- **Model Used**: `gemini-2.0-flash`

---

## 🎯 Intelligence Integrations

### 1. NVD REST API 2.0 (`get_cve`)
- Extracted `CVE-YYYY-NNNN` pattern IDs are queried against the National Vulnerability Database API.
- Extracts CVSS v3.1 base score, severity rating, metrics vector string, and vulnerability summary.

### 2. Local STIX MITRE ATT&CK Mapping
- Searches local Enterprise ATT&CK matrix mappings for matching tactics and technique IDs (e.g. `T1190` Exploit Public-Facing Application, `T1059` Command & Scripting Interpreter).

---

## 🛠️ Automated Rule Generation

The agent automatically generates production-ready detection rules:

1. **Sigma Rules (SIEM Detection)**:
   - Structured YAML rules for Splunk, Elastic, and QRadar.
2. **YARA Rules (Endpoint & Malware Hunting)**:
   - Custom string signatures and hex conditions for memory and disk scanning.
3. **Splunk SPL Queries**:
   - Ready-to-execute search queries for SOC analysts.
