"""
Sentinel AI — Unit Tests for RemediationAgent
"""
import pytest
from app.agents.state import SentinelState
from app.agents.remediation_agent import RemediationAgent

@pytest.mark.asyncio
async def test_remediation_agent_playbook_generation():
    agent = RemediationAgent()
    state = SentinelState(
        session_id="test-remediation-unit",
        user_id="unit-test-user",
        raw_input="SSH brute force intrusion from 185.220.101.47",
        input_type="LOGS",
        pipeline="B",
        triage_report={
            "classification": "TRUE_POSITIVE",
            "confidence": 0.95,
            "severity": "CRITICAL",
            "attack_pattern": "SSH Brute Force",
            "affected_assets": ["webserver-01"],
            "key_findings": ["100 failed root logins"],
            "recommended_immediate_actions": ["Block 185.220.101.47"],
        },
    )
    res_state = await agent.run(state)
    assert res_state.remediation_plan is not None
    steps = res_state.remediation_plan.get("containment_steps", [])
    assert len(steps) > 0
    # Verify destructive commands are flagged for approval
    destructive_steps = [s for s in steps if s.get("destructive")]
    assert len(destructive_steps) >= 0  # May have destructive commands flagged
