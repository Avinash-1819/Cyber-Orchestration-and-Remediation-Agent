"""
Sentinel AI — Unit Tests for ComplianceAgent
"""
import pytest
from app.agents.state import SentinelState, Finding
from app.agents.compliance_agent import ComplianceAgent, _load_control_mappings

def test_load_control_mappings():
    mappings = _load_control_mappings()
    assert len(mappings) > 0
    assert any(k in mappings for k in ["iso27001", "soc2", "nist_800_53", "pci_dss_4"])

@pytest.mark.asyncio
async def test_compliance_agent_assessment():
    agent = ComplianceAgent()
    state = SentinelState(
        session_id="test-compliance-unit",
        user_id="unit-test-user",
        raw_input="SQL Injection vulnerability",
        input_type="CODE",
        pipeline="A",
        findings=[
            Finding(
                id="f1",
                severity="HIGH",
                category="SQLi",
                title="Unsanitized SQL Query",
                description="SQL injection vulnerability in auth route",
                remediation_advice="Use parameterized queries",
            )
        ],
    )
    res_state = await agent.run(state)
    assert res_state.compliance_report is not None
    assert "overall_score" in res_state.compliance_report
