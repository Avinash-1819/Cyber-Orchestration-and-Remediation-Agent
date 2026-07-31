"""
Sentinel AI — Agent Documentation Generator Service
Generates technical PDF manuals for all 12 sub-agents on app startup.
"""
import os
import structlog
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable

log = structlog.get_logger(__name__)

DOCS_OUTPUT_DIR = Path("/app/data/agent_docs/pdf")

ENHANCED_AGENT_DOCS = [
    {
        "filename": "01_Incident_Triage_Agent_Documentation.pdf",
        "title": "Incident Triage Agent (Agent 1)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Incident Triage Agent is the primary defensive analysis component responsible for processing security logs, network events, and threat signals. It parses unformatted event streams, extracts indicators of compromise (IOCs) using regular expression engines, enriches them against external threat intelligence APIs, and performs LLM-driven classification.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Entry node for Pipeline B (Incident Response Pipeline) and Pipeline A_THEN_B.",
                "Input Ingestion: Accepts raw syslog strings, Windows Event Logs (EVTX JSON), firewall logs, NIDS/NIPS alerts (Suricata/Snort), and cloud audit trails.",
                "State Propagation: Populates state.extracted_iocs and state.triage_report in the central SentinelState data structure.",
                "Execution Latency: Sub-3 second execution utilizing gemini-2.0-flash with Grafify token compaction."
            ]),
            ("2. IOC Extraction & Regular Expressions Engine", [
                "IPv4 Regex: Matches public IPv4 addresses while automatically filtering private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1/8).",
                "Domain Regex: Matches top-level domains (.com, .net, .org, .io, .ru, .cn, .xyz, etc.) with RFC-compliant validation.",
                "Cryptographic Hashes: Extracts MD5 (32-hex), SHA-1 (40-hex), and SHA-256 (64-hex) hashes from log messages and file transfer events.",
                "Deduplication: Automatically deduplicates duplicate IOCs while preserving first-seen and last-seen timestamp metadata."
            ]),
            ("3. Real-Time External API Integrations", [
                "VirusTotal API v3: Asynchronously queries /api/v3/ip_addresses/{ip}, /domains/{domain}, and /files/{hash}. Extracts last_analysis_stats (malicious, suspicious, harmless votes) and threat categories.",
                "Shodan REST API: Queries /shodan/host/{ip} to retrieve host OS, ISP attribution, hostnames, and active open ports (e.g. 22/SSH, 80/HTTP, 445/SMB, 3389/RDP).",
                "Fallback & Resilience: Gracefully degrades to local heuristic scoring if API keys are exhausted or external endpoints experience timeout."
            ]),
            ("4. LLM Triage Analysis & Output Schema", [
                "True/False Positive Classification: Evaluates whether log signals represent an authentic security breach or benign network noise.",
                "Severity Scoring: Assigns CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL severity based on threat impact and asset exposure.",
                "Schema Contract (TriageAnalysisSchema): Output strictly validated via Pydantic schema containing classification, confidence, attack_pattern, affected_assets, key_findings, and recommended_immediate_actions."
            ])
        ]
    },
    {
        "filename": "02_Remediation_Agent_Documentation.pdf",
        "title": "Remediation Agent (Agent 2)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Remediation Agent converts high-severity security incident findings into actionable, multi-platform containment playbooks, automated isolation scripts, and long-term security hardening measures while enforcing safety approval gates for destructive commands.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Second node in Pipeline B, executing directly after IncidentTriageAgent.",
                "Context Consumption: Consumes state.triage_report, state.extracted_iocs, and state.findings.",
                "State Propagation: Writes state.remediation_plan containing step-by-step mitigation commands.",
                "Human-in-the-Loop Safety: Enforces mandatory approval gates for commands that disrupt production services."
            ]),
            ("2. Multi-OS Command Generation Engine", [
                "Linux CLI: Generates iptables firewall drop rules, ufw block commands, systemctl service termination, and pkill process isolation.",
                "Windows PowerShell: Generates Stop-Process, New-NetFirewallRule, and Disable-LocalUser scripts.",
                "Kubernetes Container Engine: Generates kubectl cordon node isolation, kubectl delete pod, and network policy restriction manifests.",
                "Cloud IAM & Infrastructure: Generates AWS CLI commands (aws ec2 revoke-security-group-ingress, aws iam detach-user-policy)."
            ]),
            ("3. Destructive Action Flagging & Safety Gates", [
                "Classification Rules: Commands that terminate active database connections, reboot servers, or delete storage volumes are flagged with is_destructive: true.",
                "UI Gate Enforcement: The frontend interface intercepts destructive actions and displays a modal requiring typing 'APPROVE' before copying or executing.",
                "Justification Audit Log: Every generated command includes a mandatory technical justification string for SOC compliance logging."
            ]),
            ("4. Output Schema & Playbook Structure", [
                "RemediationAction Schema: Contains step_number, action_type (CONTAINMENT, ISOLATION, ERADICATION, RECOVERY), title, command, is_destructive, and justification.",
                "Long-Term Hardening: Provides architectural guidance for preventing recurrent exploitation vectors."
            ])
        ]
    },
    {
        "filename": "03_DevSecOps_Agent_Documentation.pdf",
        "title": "DevSecOps Agent (Agent 3)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The DevSecOps Agent provides comprehensive Static Application Security Testing (SAST), secret detection, Dockerfile container audits, and Infrastructure-as-Code (IaC) Terraform auditing across enterprise software repositories.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Primary analysis node for Pipeline A (DevSecOps Pipeline) and Pipeline A_THEN_B.",
                "Repository Ingestion: Supports direct code input as well as asynchronous cloning of public/private GitHub repositories (git clone).",
                "State Propagation: Populates state.code_audit_report and appends SAST findings to state.findings."
            ]),
            ("2. Local High-Precision Secret Detection", [
                "Pre-LLM Regex Scanning: Scans raw source files for credentials before submitting code to external models.",
                "Pattern Library: Detects AWS Access Key IDs (AKIA...), GitHub Tokens (ghp_...), JWT Tokens, Bearer Tokens, and Private Keys.",
                "Redaction Guarantee: Masking algorithm shows only the first 4 and last 4 characters (e.g., AKIA****EXAMPLEKEY) to prevent credential leakage."
            ]),
            ("3. Container & Infrastructure-as-Code Audits", [
                "Dockerfile Auditing: Identifies root container execution (USER root), unpinned base images (ubuntu:latest), and exposed build-arg credentials.",
                "Terraform IaC Auditing: Identifies overly permissive security group ingress rules (0.0.0.0/0), public S3 bucket ACLs, and unencrypted EBS volumes."
            ]),
            ("4. Code Refactoring & Remediation Advice", [
                "Vulnerable Snippets: Extracts exact file paths and line numbers where vulnerabilities reside.",
                "Secure Fix Snippets: Generates drop-in, refactored code snippets implementing parameterized SQL queries, sanitized inputs, and secure environment variable access."
            ])
        ]
    },
    {
        "filename": "04_Compliance_Agent_Documentation.pdf",
        "title": "Compliance Agent (Agent 4)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Compliance Agent evaluates technical security findings against major global Governance, Risk, and Compliance (GRC) control frameworks, producing automated audit evidence checklists and quantitative compliance ratings.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Executes after DevSecOpsAgent in Pipeline A and Pipeline A_THEN_B.",
                "State Mapping: Maps all accumulated vulnerabilities in state.findings to formal compliance control IDs.",
                "State Propagation: Writes state.compliance_report and updates state.findings with framework control tags."
            ]),
            ("2. Supported GRC Framework Datasets (YAML)", [
                "ISO 27001:2022: Maps to Controls A.5.15 (Access Control), A.8.8 (Management of Technical Vulnerabilities), and A.8.24 (Use of Cryptography).",
                "SOC 2 Type II: Maps to Trust Services Criteria CC6.1 (Logical Access), CC6.6 (Boundary Protection), and CC7.1 (Vulnerability Monitoring).",
                "NIST SP 800-53 Rev 5: Maps to Control Families AC (Access Control), SI (System Integrity), and SC (System & Communications Protection).",
                "PCI DSS 4.0: Maps to Requirements 2 (Apply Secure Configurations), 3 (Protect Stored Account Data), 6 (Develop Secure Systems), and 8 (Identify & Authenticate)."
            ]),
            ("3. Quantitative Compliance Scoring Algorithm", [
                "Score Equation: Score = max(0, 100 - (Critical_Count * 25 + High_Count * 15 + Medium_Count * 5)).",
                "Auditor Evidence Checklist: Generates structured Pass/Fail verification items with explicit justification for external audit submission."
            ])
        ]
    },
    {
        "filename": "05_Threat_Intel_Agent_Documentation.pdf",
        "title": "Threat Intelligence Agent (Agent 5)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Threat Intelligence Agent queries vulnerability databases, maps attack techniques to the MITRE ATT&CK Enterprise matrix, assesses weaponization risk, and generates production-ready detection signatures (Sigma, YARA, Splunk SPL).",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Primary node in Pipeline C (Threat Intel) and third node in Pipeline B.",
                "Input Processing: Extracts CVE identifiers (CVE-YYYY-NNNN) and attack descriptions from state.",
                "State Propagation: Writes state.threat_intel_report containing CVE CVSS scores, MITRE mappings, and generated detection rules."
            ]),
            ("2. National Vulnerability Database (NVD 2.0) Integration", [
                "NVD REST API 2.0: Queries https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id} asynchronously.",
                "Extracted Metrics: Retrieves CVSS v3.1 base score, severity rating, vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), and published timestamps."
            ]),
            ("3. MITRE ATT&CK Enterprise Matrix Mapping", [
                "Local STIX Dataset: Queries Enterprise ATT&CK matrix for tactics and technique IDs (e.g., T1190 Exploit Public-Facing Application, T1059 Command & Scripting Interpreter).",
                "Context Alignment: Aligns mapped techniques with incident triage findings."
            ]),
            ("4. Automated Detection Rule Generation Engine", [
                "Sigma Rules: Generates valid YAML Sigma detection rules for SIEM deployment.",
                "YARA Rules: Generates memory and disk scanning YARA rules with hex/string patterns.",
                "Splunk SPL: Generates ready-to-use search queries for SOC monitoring dashboards."
            ])
        ]
    },
    {
        "filename": "06_Exec_Reporting_Agent_Documentation.pdf",
        "title": "Executive Reporting Agent (Agent 6)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Executive Reporting Agent is the final synthesis node in the CORE pipeline graph. It aggregates all sub-agent findings into executive summaries, computes session risk ratings, and powers multi-format export engines for PDF, Markdown, and JSON reports.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Mandatory final node across ALL pipelines (Pipeline A, B, C, A_THEN_B, CUSTOM).",
                "State Synthesis: Consolidates state.triage_report, state.remediation_plan, state.code_audit_report, state.compliance_report, and state.threat_intel_report.",
                "State Propagation: Writes state.executive_summary and triggers backend report generation."
            ]),
            ("2. Multi-Format Report Generation Engine", [
                "ReportLab PDF Report (GET /api/v1/reports/{session_id}/pdf): Generates multi-page PDF featuring executive summary, severity metrics pie chart, findings table, remediation playbooks, and compliance gap analysis.",
                "Markdown Report (GET /api/v1/reports/{session_id}/markdown): Formatted briefing suitable for ticketing platforms (Jira, GitHub Issues).",
                "JSON Report (GET /api/v1/reports/{session_id}/json): Serialized SentinelState Pydantic v2 data model."
            ]),
            ("3. Session Risk Rating Matrix", [
                "CRITICAL Risk: Assigned if >= 1 Critical finding or active breach detected.",
                "HIGH Risk: Assigned if >= 1 High severity vulnerability or unpatched CVE exists.",
                "MEDIUM / LOW Risk: Assigned for non-critical hardening recommendations."
            ])
        ]
    },
    {
        "filename": "07_IOC_Enrichment_Agent_Documentation.pdf",
        "title": "IOC Enrichment Agent (Agent 7)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The IOC Enrichment Agent takes raw indicators of compromise extracted by triage and enriches them against external threat intelligence platforms (VirusTotal, Shodan) and local deterministic reputation heuristics, producing a consolidated, risk-weighted IOC registry.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Second node in Pipeline B, executing directly after IncidentTriageAgent.",
                "Input Consumption: Consumes state.extracted_iocs (IPs, domains, hashes, URLs).",
                "State Propagation: Writes state.ioc_enrichment_report and updates findings with per-IOC reputation context.",
                "Graceful Degradation: Never fails the pipeline when external APIs are unreachable; deterministic heuristics fill the gap."
            ]),
            ("2. Multi-Source Enrichment Layer", [
                "VirusTotal API v3: Reputation votes (malicious/suspicious/harmless), country attribution, and tags per IOC.",
                "Shodan REST API: Open-port inventory, ISP, hostnames, and known vulnerabilities for exposed IPs.",
                "Local Deterministic Heuristics: Private-range classification, reserved multicast/loopback detection, hash format validation, and static reputation scoring."
            ]),
            ("3. Risk-Weighted IOC Registry", [
                "Threat Score: Each IOC receives a normalized 0-100 risk score combining external votes and local heuristics.",
                "Confidence Labeling: IOCs are labeled MALICIOUS, SUSPICIOUS, or BENIGN with evidence from each contributing source.",
                "Deduplication: Consolidates repeated indicators while preserving first-seen/last-seen provenance."
            ]),
            ("4. Output Schema & Downstream Handoff", [
                "IOCEnrichmentReport: Contains enriched_iocs list, threat_summary, and overall threat_score.",
                "Downstream Consumption: LogCorrelationAgent and ForensicsAgent consume enriched IOC context for behavioral correlation."
            ])
        ]
    },
    {
        "filename": "08_Log_Correlation_Agent_Documentation.pdf",
        "title": "Log Correlation Agent (Agent 8)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Log Correlation Agent performs deterministic time-series correlation across firewall, IDS/IPS, authentication, and endpoint event streams to detect multi-stage attack chains that individual log entries would miss.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Third node in Pipeline B, executing after IOCEnrichmentAgent.",
                "Input Consumption: Consumes raw log payloads, enriched IOCs, and triage context.",
                "State Propagation: Writes state.log_correlation_report with correlated event clusters and attack-chain hypotheses."
            ]),
            ("2. Deterministic Correlation Engine", [
                "Source IP Clustering: Groups events sharing a source address within a configurable time window.",
                "Port/Service Chaining: Maps sequential port-scan to service-access to privilege-escalation patterns.",
                "Authentication Failure Counting: Flags brute-force attempts exceeding deterministic thresholds (e.g., >5 failures/minute).",
                "Temporal Window Analysis: Only events inside the correlation window are chained, preventing false-positive merging."
            ]),
            ("3. Attack-Chain Hypothesis Generation", [
                "Chain Reconstruction: Each correlated cluster produces a human-readable hypothesis of the likely attack flow.",
                "Confidence Scoring: Chain confidence reflects evidence volume and consistency across independent log sources.",
                "Alert Fatigue Reduction: Correlated clusters are surfaced once with full evidence rather than as disjointed alerts."
            ])
        ]
    },
    {
        "filename": "09_Forensics_Agent_Documentation.pdf",
        "title": "Digital Forensics Agent (Agent 9)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Forensics Agent conducts deterministic evidence extraction and artifact analysis over the incident data, identifying persistence mechanisms, timelining suspicious activity, and mapping attack artifacts to MITRE ATT&CK techniques.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Fourth node in Pipeline B, executing after LogCorrelationAgent.",
                "Input Consumption: Consumes correlated event clusters, enriched IOCs, and raw payloads.",
                "State Propagation: Writes state.forensics_report with evidence artifacts, timeline, and persistence findings."
            ]),
            ("2. Artifact & Persistence Analysis", [
                "Persistence Pattern Detection: Startup keys, cron entries, scheduled tasks, and registry autorun references.",
                "Process/Service Artifacts: Suspicious binaries, unusual child-process chains, and service registration anomalies.",
                "File-Hash Attribution: Links discovered hashes to known-bad reputation from the enrichment layer."
            ]),
            ("3. Incident Timeline Reconstruction", [
                "Chronological Evidence Ledger: Every artifact is stamped with its first-seen event reference.",
                "Kill-Chain Positioning: Each artifact is mapped to a MITRE ATT&CK tactic for analyst navigation.",
                "Chain-of-Custody Fields: Evidence entries include source log reference and detection method for auditability."
            ])
        ]
    },
    {
        "filename": "10_Cloud_Security_Agent_Documentation.pdf",
        "title": "Cloud Security Agent (Agent 10)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Cloud Security Agent performs deterministic auditing of infrastructure-as-code (Terraform, CloudFormation), container configurations (Docker), and cloud service posture to detect misconfigurations, exposed secrets, and privilege escalations across AWS, Azure, and GCP.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Second node in Pipeline A, executing after DevSecOpsAgent.",
                "Input Consumption: Consumes code audit findings (including secret-redacted file snippets) and raw IaC payloads.",
                "State Propagation: Writes state.cloud_security_report with per-service misconfiguration findings."
            ]),
            ("2. IaC Misconfiguration Detection", [
                "Terraform/CloudFormation: Detects public S3 buckets, overly permissive security groups (0.0.0.0/0), unencrypted volumes, and IAM wildcard privileges.",
                "Docker Security Posture: Flags root execution, unversioned base images, missing healthchecks, and sensitive env passthrough.",
                "Service Posture: Checks AWS/GCP/Azure managed-service settings embedded in configuration code."
            ]),
            ("3. Deterministic Risk Assignment", [
                "CIS Benchmark Alignment: Findings reference aligned CIS benchmark controls.",
                "Severity Classification: CRITICAL/HIGH/MEDIUM/LOW based on exploitability and blast radius.",
                "Remediation Guidance: Every finding ships with a concrete configuration fix snippet."
            ])
        ]
    },
    {
        "filename": "11_Network_Security_Agent_Documentation.pdf",
        "title": "Network Security Agent (Agent 11)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Network Security Agent performs deterministic analysis of network topology data, firewall rule sets, open-port inventories, and exposure lists to identify attack surface, lateral movement paths, and risky perimeter configurations.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Sole analysis node in Pipeline D (Network Exposure).",
                "Input Consumption: Accepts nmap-style output, IP:port inventories, firewall rules, and topology descriptions.",
                "State Propagation: Writes state.network_security_report and appends exposure findings."
            ]),
            ("2. Exposure & Attack-Surface Analysis", [
                "Open-Port Risk Scoring: Ranks exposed services (e.g., 22/SSH, 3389/RDP, 445/SMB, 1433/MSSQL) by exploitation likelihood.",
                "Firewall Rule Review: Flags default-deny violations, wildcard source ranges, and management-plane exposure.",
                "Lateral-Movement Paths: Identifies host pairs where a compromise on one node directly reaches another."
            ]),
            ("3. Deterministic Segmentation & Hardening Output", [
                "Segmentation Recommendations: Produces allow-list and network-tier suggestions derived from observed flows.",
                "Findings Enrichment: Each exposure finding includes severity, affected asset, and concrete hardening step."
            ])
        ]
    },
    {
        "filename": "12_Risk_Scoring_Agent_Documentation.pdf",
        "title": "Risk Scoring Agent (Agent 12)",
        "subtitle": "Deep Technical Specification & Operational Manual",
        "overview": "The Risk Scoring Agent consolidates all downstream agent outputs into a normalized, deterministic risk posture: per-asset risk scores, an overall session risk rating, and a ranked remediation priority queue.",
        "sections": [
            ("1. Architectural Overview & Workflow", [
                "Position in LangGraph Engine: Penultimate node in Pipelines A, B, A_THEN_B, and D, immediately before ExecReportingAgent.",
                "Input Consumption: Consumes triage, remediation, threat intel, compliance, cloud, network, and forensics reports.",
                "State Propagation: Writes state.risk_report with scores, rating, and priority queue."
            ]),
            ("2. Deterministic Scoring Methodology", [
                "Per-Asset Risk Score: Weighted combination of finding severities, CVSS bands, and exposure context.",
                "Overall Session Rating: Derived from worst-case asset score and critical-finding count.",
                "Remediation Priority Queue: Orders remediation actions by risk delta per unit of effort (business impact weighting)."
            ]),
            ("3. Transparency & Reproducibility", [
                "Score Breakdown: Every numeric score includes its contributing factors so analysts can audit the math.",
                "No ML, No Black Boxes: Scoring is a fully deterministic rule set — reproducible across runs."
            ])
        ]
    }
]

def generate_pdf(doc_info, target_dir: Path):
    target_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = target_dir / doc_info["filename"]
    
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=22, leading=26,
        textColor=colors.HexColor('#4F46E5'), fontName='Helvetica-Bold', spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle', parent=styles['Normal'], fontSize=12, leading=15,
        textColor=colors.HexColor('#475569'), fontName='Helvetica-Oblique', spaceAfter=12
    )
    overview_style = ParagraphStyle(
        'OverviewText', parent=styles['Normal'], fontSize=10, leading=14,
        textColor=colors.HexColor('#1E293B'), fontName='Helvetica', spaceAfter=15
    )
    section_heading_style = ParagraphStyle(
        'SectionHeading', parent=styles['Heading2'], fontSize=13, leading=16,
        textColor=colors.HexColor('#1E293B'), fontName='Helvetica-Bold', spaceBefore=14, spaceAfter=6
    )
    bullet_style = ParagraphStyle(
        'BulletText', parent=styles['Normal'], fontSize=9.5, leading=13.5,
        textColor=colors.HexColor('#334155'), fontName='Helvetica', leftIndent=15, spaceAfter=4
    )
    
    elements = []
    elements.append(Paragraph(doc_info["title"], title_style))
    elements.append(Paragraph(doc_info["subtitle"], subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#4F46E5'), spaceAfter=12))
    
    elements.append(Paragraph("<b>Executive Overview & Purpose</b>", section_heading_style))
    elements.append(Paragraph(doc_info["overview"], overview_style))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#E2E8F0'), spaceAfter=10))

    for section_title, bullets in doc_info["sections"]:
        elements.append(Paragraph(section_title, section_heading_style))
        for bullet in bullets:
            elements.append(Paragraph(f"• {bullet}", bullet_style))
        elements.append(Spacer(1, 6))
        
    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#CBD5E1'), spaceAfter=10))
    footer_text = Paragraph("<font color='#64748B' size=8>CORE (Cyber Orchestration Engine) — Agent Technical Manual PDF</font>", styles['Normal'])
    elements.append(footer_text)
    
    doc.build(elements)

def ensure_all_agent_pdfs_generated():
    """Generate all agent documentation PDFs in standard output directories."""
    paths_to_generate = [
        Path("/app/data/agent_docs/pdf"),
        Path(__file__).parents[2] / "data" / "agent_docs" / "pdf",
        Path(__file__).parents[3] / "docs" / "agents" / "pdf",
    ]
    for target_dir in paths_to_generate:
        try:
            for doc_info in ENHANCED_AGENT_DOCS:
                generate_pdf(doc_info, target_dir)
            log.info("agent_pdfs_generated_successfully", dir=str(target_dir))
        except Exception as e:
            log.warning("agent_pdf_generation_skipped", dir=str(target_dir), error=str(e))
