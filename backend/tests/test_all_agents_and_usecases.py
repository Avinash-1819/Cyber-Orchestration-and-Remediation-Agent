"""
Sentinel AI — Comprehensive Test Suite for All 6 Agents & All Use Cases
Tests every agent individually and tests all 4 orchestration pipelines (A, B, C, A_THEN_B).
"""
import asyncio
import os
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.agents.state import SentinelState, Finding, IndicatorOfCompromise
from app.agents.triage_agent import TriageAgent, _IP_PATTERN, _PRIVATE_RANGES, _DOMAIN_PATTERN
from app.agents.remediation_agent import RemediationAgent
from app.agents.devsecops_agent import DevSecOpsAgent, _detect_secrets_in_text, _redact_secret
from app.agents.compliance_agent import ComplianceAgent
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.agents.exec_reporting_agent import ExecReportingAgent
from app.agents.orchestrator import run_pipeline, route_pipeline, classify_payload
from app.db.database import init_db


# ============================================================
# 1. INDIVIDUAL AGENT TESTS
# ============================================================

async def test_agent_1_triage_individual():
    print("\n--- Test 1: IncidentTriageAgent (Individual) ---")
    agent = TriageAgent()
    
    # Static IOC Extraction
    text = "Connection from 185.220.101.47 and 10.0.0.1 and domain malicious-c2.ru"
    ips = _IP_PATTERN.findall(text)
    public_ips = [ip for ip in ips if not any(p.match(ip) for p in _PRIVATE_RANGES)]
    domains = _DOMAIN_PATTERN.findall(text)
    
    assert "185.220.101.47" in public_ips
    assert "10.0.0.1" not in public_ips
    assert "malicious-c2.ru" in domains
    print("  ✓ IOC regex & RFC1918 filtering passed")

    # LLM Triage Execution
    state = SentinelState(
        session_id="test-triage-indiv",
        user_id="unit-tester",
        raw_input="Failed password for root from 185.220.101.47 port 22. Accepted password for ubuntu from 185.220.101.47.",
        input_type="LOGS",
        pipeline="B",
    )
    res_state = await agent.run(state)
    assert res_state.triage_report is not None
    assert res_state.triage_report.get("classification") in ["TRUE_POSITIVE", "FALSE_POSITIVE"]
    print(f"  ✓ Agent 1 run complete: classification={res_state.triage_report.get('classification')}, findings={len(res_state.findings)}")


async def test_agent_2_remediation_individual():
    print("\n--- Test 2: RemediationAgent (Individual) ---")
    agent = RemediationAgent()
    
    state = SentinelState(
        session_id="test-remediation-indiv",
        user_id="unit-tester",
        raw_input="SSH brute force intrusion detected from 185.220.101.47",
        input_type="LOGS",
        pipeline="B",
        triage_report={
            "classification": "TRUE_POSITIVE",
            "confidence": 0.95,
            "severity": "HIGH",
            "attack_pattern": "SSH Brute Force",
            "affected_assets": ["webserver-01"],
            "key_findings": ["100 failed logins"],
            "recommended_immediate_actions": ["Block IP 185.220.101.47"],
            "executive_one_liner": "SSH brute force attack contained.",
        },
    )
    res_state = await agent.run(state)
    assert res_state.remediation_plan is not None
    steps = res_state.remediation_plan.get("containment_steps", [])
    assert len(steps) > 0
    print(f"  ✓ Agent 2 run complete: containment_steps={len(steps)}, destructive_flagged={any(s.get('destructive') for s in steps)}")


async def test_agent_3_devsecops_individual():
    print("\n--- Test 3: DevSecOpsAgent (Individual) ---")
    agent = DevSecOpsAgent()

    # Secret Detection & Redaction
    code_sample = 'AWS_SECRET = "AKIA1234567890ABCDEF"\npassword = "sk-live-secretkey123456"'
    secrets = _detect_secrets_in_text(code_sample, "config.py")
    assert len(secrets) >= 1
    for s in secrets:
        assert s["redacted_value"] != "AKIA1234567890ABCDEF"
        assert "****" in s["redacted_value"]
    print("  ✓ Secret detection & redaction passed")

    # LLM SAST Execution
    vulnerable_code = """
import sqlite3
def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    state = SentinelState(
        session_id="test-devsecops-indiv",
        user_id="unit-tester",
        raw_input=vulnerable_code,
        input_type="CODE",
        pipeline="A",
    )
    res_state = await agent.run(state)
    assert res_state.code_audit_report is not None
    assert len(res_state.findings) > 0
    print(f"  ✓ Agent 3 run complete: risk_level={res_state.code_audit_report.get('overall_risk_level')}, findings={len(res_state.findings)}")


async def test_agent_4_compliance_individual():
    print("\n--- Test 4: ComplianceAgent (Individual) ---")
    agent = ComplianceAgent()

    state = SentinelState(
        session_id="test-compliance-indiv",
        user_id="unit-tester",
        raw_input="SQL Injection vulnerability in login route",
        input_type="CODE",
        pipeline="A",
        findings=[
            Finding(
                id="f1",
                severity="HIGH",
                category="SQLi",
                title="Unsanitized SQL Query",
                description="SQL injection in login function",
                remediation_advice="Use parameterized queries",
            )
        ],
    )
    res_state = await agent.run(state)
    assert res_state.compliance_report is not None
    assert "overall_score" in res_state.compliance_report
    print(f"  ✓ Agent 4 run complete: overall_score={res_state.compliance_report.get('overall_score')}, controls_assessed={len(res_state.compliance_report.get('control_assessments', []))}")


async def test_agent_5_threat_intel_individual():
    print("\n--- Test 5: ThreatIntelAgent (Individual) ---")
    agent = ThreatIntelAgent()

    state = SentinelState(
        session_id="test-intel-indiv",
        user_id="unit-tester",
        raw_input="CVE-2024-3094 supply chain backdoor in xz-utils",
        input_type="CVE",
        pipeline="C",
    )
    res_state = await agent.run(state)
    assert res_state.threat_intel_report is not None
    assert len(res_state.threat_intel_report.get("detection_rules", [])) > 0
    print(f"  ✓ Agent 5 run complete: rules_generated={len(res_state.threat_intel_report.get('detection_rules', []))}, cve_found={any(c.get('cve_id') == 'CVE-2024-3094' for c in res_state.threat_intel_report.get('cve_data', []))}")


async def test_agent_6_exec_reporting_individual():
    print("\n--- Test 6: ExecReportingAgent (Individual) ---")
    agent = ExecReportingAgent()

    state = SentinelState(
        session_id="test-exec-indiv",
        user_id="unit-tester",
        raw_input="Critical security incident",
        input_type="LOGS",
        pipeline="B",
        findings=[
            Finding(
                id="f1",
                severity="CRITICAL",
                category="Incident",
                title="Unauthorized SSH Intrusion",
                description="Attacker gained root access",
                remediation_advice="Isolate server immediately",
            )
        ],
    )
    res_state = await agent.run(state)
    assert res_state.executive_summary is not None
    assert res_state.report_pdf_path and os.path.exists(res_state.report_pdf_path)
    assert res_state.report_markdown_path and os.path.exists(res_state.report_markdown_path)
    assert res_state.report_json_path and os.path.exists(res_state.report_json_path)
    print(f"  ✓ Agent 6 run complete: reports generated (PDF={os.path.basename(res_state.report_pdf_path)})")


# ============================================================
# 2. FULL PIPELINE END-TO-END TESTS (A, B, C, A_THEN_B)
# ============================================================

async def test_full_pipelines():
    print("\n==========================================")
    print("RUNNING FULL PIPELINE END-TO-END TESTS")
    print("==========================================")

    # 1. Pipeline A (CODE)
    print("\n[Pipeline A] Code SAST & Compliance...")
    state_a = SentinelState(
        session_id="e2e-pipeline-a",
        user_id="tester",
        raw_input="""
import sqlite3
def search(term):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE name LIKE '%{term}%'")
    return cursor.fetchall()
""",
        input_type="CODE",
        pipeline="A",
    )
    res_a = await run_pipeline(state_a)
    assert res_a.status == "completed"
    assert res_a.code_audit_report is not None
    assert res_a.compliance_report is not None
    print(f"  ✓ Pipeline A Passed! Status: {res_a.status}, Findings: {len(res_a.findings)}")

    # 2. Pipeline B (LOGS)
    print("\n[Pipeline B] Incident Triage & Remediation...")
    state_b = SentinelState(
        session_id="e2e-pipeline-b",
        user_id="tester",
        raw_input="Failed password for root from 198.51.100.42 port 44321 ssh2\nAccepted password for ubuntu from 198.51.100.42",
        input_type="LOGS",
        pipeline="B",
    )
    res_b = await run_pipeline(state_b)
    assert res_b.status == "completed"
    assert res_b.triage_report is not None
    assert res_b.remediation_plan is not None
    print(f"  ✓ Pipeline B Passed! Status: {res_b.status}, Findings: {len(res_b.findings)}")

    # 3. Pipeline C (CVE)
    print("\n[Pipeline C] Threat Intelligence Query...")
    state_c = SentinelState(
        session_id="e2e-pipeline-c",
        user_id="tester",
        raw_input="CVE-2024-3094 xz utils backdoor",
        input_type="CVE",
        pipeline="C",
    )
    res_c = await run_pipeline(state_c)
    assert res_c.status == "completed"
    assert res_c.threat_intel_report is not None
    print(f"  ✓ Pipeline C Passed! Status: {res_c.status}, Findings: {len(res_c.findings)}")

    # 4. Pipeline A_THEN_B (MIXED)
    print("\n[Pipeline A_THEN_B] Mixed Code Audit + Incident Triage...")
    state_mixed = SentinelState(
        session_id="e2e-pipeline-mixed",
        user_id="tester",
        raw_input="""
Vulnerable auth endpoint:
def login(req):
    query = "SELECT * FROM users WHERE user = '" + req.user + "'"
    db.execute(query)

Server log:
Jul 29 14:00:00 server sshd: Failed password for root from 203.0.113.19
""",
        input_type="MIXED",
        pipeline="A_THEN_B",
    )
    res_mixed = await run_pipeline(state_mixed)
    assert res_mixed.status == "completed"
    assert res_mixed.code_audit_report is not None
    assert res_mixed.triage_report is not None
    print(f"  ✓ Pipeline A_THEN_B Passed! Status: {res_mixed.status}, Total Findings: {len(res_mixed.findings)}")


async def main():
    print("========================================================")
    print("🧪 SENTINEL AI — ALL AGENTS & USE CASES TEST SUITE")
    print("========================================================")
    await init_db()

    # Individual Agent Unit Tests
    await test_agent_1_triage_individual()
    await test_agent_2_remediation_individual()
    await test_agent_3_devsecops_individual()
    await test_agent_4_compliance_individual()
    await test_agent_5_threat_intel_individual()
    await test_agent_6_exec_reporting_individual()

    # Full End-to-End Pipeline Tests
    await test_full_pipelines()

    print("\n========================================================")
    print("🎉 ALL 6 AGENTS AND ALL 4 PIPELINES PASSED 100% CLEANLY!")
    print("========================================================\n")

if __name__ == "__main__":
    asyncio.run(main())
