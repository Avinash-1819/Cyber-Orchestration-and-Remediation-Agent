"""
Sentinel AI — Automated Multi-Format Report Engine Tests
Tests PDF, Markdown, and JSON report generation under critical, high, and compliant scenario inputs.
"""
import os
import pytest
from app.agents.state import SentinelState, Finding
from app.services.report_engine import generate_all_reports

@pytest.mark.asyncio
async def test_report_engine_critical_scenario(tmp_path):
    state = SentinelState(
        session_id="report-test-critical",
        user_id="qa-tester",
        raw_input="Unauthorized SSH intrusion and root privilege escalation",
        input_type="LOGS",
        pipeline="B",
        findings=[
            Finding(
                id="f1",
                severity="CRITICAL",
                category="Incident",
                title="Unauthorized Root SSH Intrusion",
                description="Attacker compromised ubuntu credentials and escalated to root.",
                remediation_advice="Isolate server and revoke SSH keys.",
            ),
            Finding(
                id="f2",
                severity="HIGH",
                category="Remediation",
                title="Revoke Compromised SSH Key",
                description="Delete /home/ubuntu/.ssh/authorized_keys",
                remediation_advice="rm -f /home/ubuntu/.ssh/authorized_keys",
            ),
        ],
    )
    
    paths = generate_all_reports(state)
    assert os.path.exists(paths["pdf"])
    assert os.path.exists(paths["markdown"])
    assert os.path.exists(paths["json"])
    assert os.path.getsize(paths["pdf"]) > 0
    assert os.path.getsize(paths["markdown"]) > 0
    assert os.path.getsize(paths["json"]) > 0

@pytest.mark.asyncio
async def test_report_engine_compliant_scenario(tmp_path):
    state = SentinelState(
        session_id="report-test-compliant",
        user_id="qa-tester",
        raw_input="Clean security audit",
        input_type="CODE",
        pipeline="A",
        findings=[],  # No findings — clean audit
    )
    
    paths = generate_all_reports(state)
    assert os.path.exists(paths["pdf"])
    assert os.path.exists(paths["markdown"])
    assert os.path.exists(paths["json"])
