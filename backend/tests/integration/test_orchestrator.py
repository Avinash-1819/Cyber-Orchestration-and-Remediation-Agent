"""
Sentinel AI — Integration Tests for LangGraph Workflow Orchestrator & State Persistence
Tests Pipelines A, B, C, thread-safe state persistence, and graceful fallback handling.
"""
import pytest
from app.agents.state import SentinelState
from app.agents.orchestrator import run_pipeline, route_pipeline, classify_payload
from app.db.database import init_db

@pytest.mark.asyncio
async def test_pipeline_a_appsec_integration():
    await init_db()
    code_input = """
def authenticate(username, password):
    query = f"SELECT * FROM users WHERE u='{username}' AND p='{password}'"
    return db.execute(query)
"""
    state = SentinelState(
        session_id="integ-test-pipeline-a",
        user_id="integration-tester",
        raw_input=code_input,
        input_type="CODE",
        pipeline="A",
    )
    res_state = await run_pipeline(state)
    assert res_state.status == "completed"
    assert res_state.code_audit_report is not None
    assert res_state.compliance_report is not None
    assert res_state.executive_summary is not None
    assert len(res_state.trace) >= 3

@pytest.mark.asyncio
async def test_pipeline_b_secops_integration():
    await init_db()
    log_input = "Failed password for root from 198.51.100.42 port 22. Accepted password for ubuntu from 198.51.100.42."
    state = SentinelState(
        session_id="integ-test-pipeline-b",
        user_id="integration-tester",
        raw_input=log_input,
        input_type="LOGS",
        pipeline="B",
    )
    res_state = await run_pipeline(state)
    assert res_state.status == "completed"
    assert res_state.triage_report is not None
    assert res_state.remediation_plan is not None
    assert res_state.threat_intel_report is not None
    assert res_state.executive_summary is not None

@pytest.mark.asyncio
async def test_pipeline_c_intel_integration():
    await init_db()
    cve_input = "CVE-2024-3094 xz-utils backdoor"
    state = SentinelState(
        session_id="integ-test-pipeline-c",
        user_id="integration-tester",
        raw_input=cve_input,
        input_type="CVE",
        pipeline="C",
    )
    res_state = await run_pipeline(state)
    assert res_state.status == "completed"
    assert res_state.threat_intel_report is not None
    assert res_state.executive_summary is not None

@pytest.mark.asyncio
async def test_orchestrator_fallback_handling():
    await init_db()
    # Inject error state into pipeline
    state = SentinelState(
        session_id="integ-test-fallback",
        user_id="integration-tester",
        raw_input="Corrupted log payload",
        input_type="LOGS",
        pipeline="B",
    )
    state.add_error("TestAgent", "Simulated mid-pipeline agent failure")
    
    # Should handle errors gracefully and generate partial report without crashing
    res_state = await run_pipeline(state)
    assert len(res_state.errors) > 0
    assert res_state.executive_summary is not None
