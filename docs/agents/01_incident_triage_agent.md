# 🔍 Incident Triage Agent (`IncidentTriageAgent`)

## Overview
The **Incident Triage Agent** processes security log streams, syslogs, firewall events, and IOC indicators. It extracts indicators of compromise using regex rules and enriches them via live third-party security intelligence APIs.

- **Source Code**: [`backend/app/agents/triage_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/triage_agent.py)
- **External Integration Services**: [`backend/app/services/external_intel.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/services/external_intel.py)
- **Model Used**: `gemini-2.0-flash`

---

## 🌐 Live API Integrations

### 1. VirusTotal API v3 (`enrich_ioc_virustotal`)
- **IP / Domain / Hash Reputation**: Queries VirusTotal endpoints asynchronously for malicious vote counts, threat category tags, and reputation scores.
- **Cache & Rate Limit**: Built-in in-memory LRU cache and exponential backoff retry.

### 2. Shodan REST API (`enrich_ip_shodan`)
- **Host Banner & Open Ports**: Queries Shodan for open ports, running services, host OS, hostnames, and ISP information for public IP addresses.

---

## 🛠️ Extracted IOC Regex Patterns

| Type | Pattern |
|---|---|
| **IPv4 Address** | `\b(?:(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\.){3}(?:25[0-5]\|2[0-4]\d\|[01]?\d\d?)\b` |
| **Domain Name** | `\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com\|net\|org\|io\|ru\|cn...)\b` |
| **SHA-256 Hash** | `\b[a-fA-F0-9]{64}\b` |
| **MD5 Hash** | `\b[a-fA-F0-9]{32}\b` |

---

## ⚡ Grafify Token Minimization
Applies `grafify_compress_logs(raw_input)` to aggregate repeating log lines (e.g. 500 SSH failure attempts) into single template representations, reducing prompt tokens by **50% to 80%**.
