"""
Sentinel AI — Unit Tests for DevSecOpsAgent
"""
import pytest
from app.agents.state import SentinelState
from app.agents.devsecops_agent import DevSecOpsAgent, _detect_secrets_in_text, _redact_secret

def test_secret_detection_and_redaction():
    text = 'AWS_SECRET_KEY = "AKIA1234567890ABCDEF"\nAPI_TOKEN = "sk-live-abcdef1234567890"'
    secrets = _detect_secrets_in_text(text, "main.py")
    assert len(secrets) >= 1
    for s in secrets:
        assert "****" in s["redacted_value"]

    redacted = _redact_secret("AKIA1234567890ABCDEF")
    assert redacted.startswith("AKIA")
    assert "****" in redacted

@pytest.mark.asyncio
async def test_devsecops_agent_audit():
    agent = DevSecOpsAgent()
    vulnerable_code = """
import sqlite3
def login(user, pwd):
    conn = sqlite3.connect('db.sqlite')
    c = conn.cursor()
    c.execute(f"SELECT * FROM users WHERE u='{user}' AND p='{pwd}'")
    return c.fetchone()
"""
    state = SentinelState(
        session_id="test-devsecops-unit",
        user_id="unit-test-user",
        raw_input=vulnerable_code,
        input_type="CODE",
        pipeline="A",
    )
    res_state = await agent.run(state)
    assert res_state.code_audit_report is not None
    assert len(res_state.findings) > 0
