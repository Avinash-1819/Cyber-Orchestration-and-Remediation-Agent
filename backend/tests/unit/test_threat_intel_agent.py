"""
Sentinel AI — Unit Tests for ThreatIntelAgent
"""
import pytest
from app.agents.state import SentinelState
from app.agents.threat_intel_agent import ThreatIntelAgent
from app.services.external_intel import search_mitre_techniques

def test_mitre_technique_search():
    results = search_mitre_techniques(["brute force", "ssh"])
    assert isinstance(results, list)

@pytest.mark.asyncio
async def test_threat_intel_agent_cve_lookup():
    agent = ThreatIntelAgent()
    state = SentinelState(
        session_id="test-intel-unit",
        user_id="unit-test-user",
        raw_input="CVE-2024-3094 supply chain backdoor in xz-utils",
        input_type="CVE",
        pipeline="C",
    )
    res_state = await agent.run(state)
    assert res_state.threat_intel_report is not None
    assert "cve_data" in res_state.threat_intel_report
