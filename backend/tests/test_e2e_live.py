"""
Sentinel AI — Live End-to-End Pipeline Verification Script
Executes Pipelines A, B, and C against sample inputs using live Gemini API.
Verifies state outputs, findings, and PDF/Markdown/JSON report generation.
"""
import asyncio
import os
import sys
from pathlib import Path

# Ensure backend root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.agents.orchestrator import run_pipeline
from app.agents.state import SentinelState


async def test_pipeline_a():
    print("\n==========================================")
    print("TESTING PIPELINE A (DevSecOps -> Compliance -> ExecReport)")
    print("==========================================")
    sample_file = backend_dir / "tests" / "sample_inputs" / "vulnerable_app.py"
    raw_input = sample_file.read_text()

    state = SentinelState(
        session_id="live-e2e-test-pipeline-a",
        user_id="e2e-tester",
        raw_input=raw_input,
        input_type="CODE",
        pipeline="A",
    )

    final_state = await run_pipeline(state)
    print(f"[*] Pipeline A Status: {final_state.status}")
    print(f"[*] Findings Count: {len(final_state.findings)}")
    print(f"[*] Summary: {final_state.finding_summary}")
    print(f"[*] Code Audit Risk Level: {final_state.code_audit_report.get('overall_risk_level') if final_state.code_audit_report else 'N/A'}")
    print(f"[*] Compliance Score: {final_state.compliance_report.get('overall_score') if final_state.compliance_report else 'N/A'}")
    print(f"[*] PDF Report Path: {final_state.report_pdf_path}")
    print(f"[*] Markdown Report Path: {final_state.report_markdown_path}")
    print(f"[*] JSON Report Path: {final_state.report_json_path}")
    
    assert final_state.status == "completed", f"Pipeline A failed: {final_state.errors}"
    assert final_state.report_pdf_path and os.path.exists(final_state.report_pdf_path), "PDF report missing"
    assert final_state.report_markdown_path and os.path.exists(final_state.report_markdown_path), "Markdown report missing"
    assert final_state.report_json_path and os.path.exists(final_state.report_json_path), "JSON report missing"
    print("[✓] PIPELINE A VERIFICATION PASSED!")
    return final_state


async def test_pipeline_b():
    print("\n==========================================")
    print("TESTING PIPELINE B (Triage -> Remediation -> ThreatIntel -> ExecReport)")
    print("==========================================")
    sample_file = backend_dir / "tests" / "sample_inputs" / "sample_syslog.txt"
    raw_input = sample_file.read_text()

    state = SentinelState(
        session_id="live-e2e-test-pipeline-b",
        user_id="e2e-tester",
        raw_input=raw_input,
        input_type="LOGS",
        pipeline="B",
    )

    final_state = await run_pipeline(state)
    print(f"[*] Pipeline B Status: {final_state.status}")
    print(f"[*] Findings Count: {len(final_state.findings)}")
    print(f"[*] Extracted IOCs Count: {len(final_state.extracted_iocs)}")
    print(f"[*] Triage Classification: {final_state.triage_report.get('classification') if final_state.triage_report else 'N/A'}")
    print(f"[*] Remediation Steps Count: {len(final_state.remediation_plan.get('containment_steps', [])) if final_state.remediation_plan else 'N/A'}")
    print(f"[*] PDF Report Path: {final_state.report_pdf_path}")

    assert final_state.status == "completed", f"Pipeline B failed: {final_state.errors}"
    assert final_state.report_pdf_path and os.path.exists(final_state.report_pdf_path), "PDF report missing"
    print("[✓] PIPELINE B VERIFICATION PASSED!")
    return final_state


async def test_pipeline_c():
    print("\n==========================================")
    print("TESTING PIPELINE C (ThreatIntel -> ExecReport)")
    print("==========================================")
    raw_input = "Please analyze threat intelligence for CVE-2024-3094 (XZ Utils backdoor)."

    state = SentinelState(
        session_id="live-e2e-test-pipeline-c",
        user_id="e2e-tester",
        raw_input=raw_input,
        input_type="CVE",
        pipeline="C",
    )

    final_state = await run_pipeline(state)
    print(f"[*] Pipeline C Status: {final_state.status}")
    print(f"[*] Findings Count: {len(final_state.findings)}")
    print(f"[*] Threat Intel Summary: {final_state.threat_intel_report.get('threat_summary')[:150] if final_state.threat_intel_report else 'N/A'}...")
    print(f"[*] Detection Rules Count: {len(final_state.threat_intel_report.get('detection_rules', [])) if final_state.threat_intel_report else 'N/A'}")
    print(f"[*] PDF Report Path: {final_state.report_pdf_path}")

    assert final_state.status == "completed", f"Pipeline C failed: {final_state.errors}"
    assert final_state.report_pdf_path and os.path.exists(final_state.report_pdf_path), "PDF report missing"
    print("[✓] PIPELINE C VERIFICATION PASSED!")
    return final_state


async def main():
    print("Initializing database tables...")
    from app.db.database import init_db
    await init_db()
    print("Starting Live End-to-End Verification of Sentinel AI Agents...")
    try:
        await test_pipeline_a()
        await test_pipeline_b()
        await test_pipeline_c()
        print("\n==========================================")
        print("🎉 ALL 3 PIPELINES VERIFIED SUCCESSFULLY!")
        print("==========================================")
    except Exception as e:
        print(f"\n[X] Verification failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
