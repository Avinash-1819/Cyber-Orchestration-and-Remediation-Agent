"""
Sentinel AI — Unit Tests for ExecReportingAgent
"""
import os
import pytest
from app.agents.state import SentinelState, Finding
from app.agents.exec_reporting_agent import ExecReportingAgent

@pytest.mark.asyncio
async def test_reporting_agent_report_generation():
    agent = ExecReportingAgent()
    state = SentinelState(
        session_id="test-reporting-unit",
        user_id="unit-test-user",
        raw_input="Critical SSH Intrusion",
        input_type="LOGS",
        pipeline="B",
        findings=[
            Finding(
                id="f1",
                severity="CRITICAL",
                category="Incident",
                title="Unauthorized SSH Root Intrusion",
                description="Brute force login succeeded",
                remediation_advice="Isolate server immediately",
            )
        ],
    )
    res_state = await agent.run(state)
    assert res_state.executive_summary is not None
    assert res_state.report_pdf_path and os.path.exists(res_state.report_pdf_path)
    assert res_state.report_markdown_path and os.path.exists(res_state.report_markdown_path)
    assert res_state.report_json_path and os.path.exists(res_state.report_json_path)
