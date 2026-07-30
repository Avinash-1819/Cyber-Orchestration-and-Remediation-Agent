"""
Sentinel AI — Unit Tests for IncidentTriageAgent
"""
import pytest
from app.agents.state import SentinelState
from app.agents.triage_agent import TriageAgent, _IP_PATTERN, _PRIVATE_RANGES, _DOMAIN_PATTERN

@pytest.mark.asyncio
async def test_triage_agent_ioc_regex():
    sample_text = (
        "Failed login from 185.220.101.47 and internal 192.168.1.5 and 10.0.0.1. "
        "Outbound connection to malicious-domain.com."
    )
    ips = _IP_PATTERN.findall(sample_text)
    public_ips = [ip for ip in ips if not any(p.match(ip) for p in _PRIVATE_RANGES)]
    domains = _DOMAIN_PATTERN.findall(sample_text)

    assert "185.220.101.47" in public_ips
    assert "192.168.1.5" not in public_ips
    assert "10.0.0.1" not in public_ips
    assert "malicious-domain.com" in domains

@pytest.mark.asyncio
async def test_triage_agent_execution():
    agent = TriageAgent()
    state = SentinelState(
        session_id="test-triage-unit",
        user_id="unit-test-user",
        raw_input="Failed password for root from 185.220.101.47 port 22 ssh2",
        input_type="LOGS",
        pipeline="B",
    )
    res_state = await agent.run(state)
    assert res_state.triage_report is not None
    assert "classification" in res_state.triage_report
    assert res_state.triage_report["classification"] in ["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_CLARIFICATION"]
