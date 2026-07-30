"""
Sentinel AI — Backend Tests
Run with: pytest tests/ -v
"""
import asyncio
import pytest
import pytest_asyncio

from app.agents.state import Finding, IndicatorOfCompromise, SentinelState
from app.core.security import create_access_token, decode_token, extract_user_id
from app.agents.triage_agent import TriageAgent


# ============================================================
# State Model Tests
# ============================================================

def test_sentinel_state_defaults():
    state = SentinelState(
        session_id="test-session",
        user_id="test-user",
        raw_input="test input",
        input_type="LOGS",
        pipeline="B",
    )
    assert state.status == "running"
    assert state.findings == []
    assert state.extracted_iocs == []
    assert state.execution_trace == []


def test_append_trace_immutable():
    state = SentinelState(
        session_id="test-session",
        user_id="test-user",
        raw_input="test input",
        input_type="LOGS",
        pipeline="B",
    )
    state.append_trace("TestAgent", "started")
    state.append_trace("TestAgent", "completed")
    assert len(state.execution_trace) == 2
    assert state.execution_trace[0].event == "started"
    assert state.execution_trace[1].event == "completed"


def test_finding_summary():
    state = SentinelState(
        session_id="test-session",
        user_id="test-user",
        raw_input="test input",
        input_type="LOGS",
        pipeline="B",
    )
    state.findings.append(Finding(id="1", severity="CRITICAL", category="Test", title="T1", description="D"))
    state.findings.append(Finding(id="2", severity="HIGH", category="Test", title="T2", description="D"))
    state.findings.append(Finding(id="3", severity="HIGH", category="Test", title="T3", description="D"))

    summary = state.finding_summary
    assert summary["CRITICAL"] == 1
    assert summary["HIGH"] == 2
    assert summary["total"] == 3


# ============================================================
# JWT Tests
# ============================================================

def test_jwt_round_trip():
    """Test that we can create and decode a JWT correctly."""
    import os
    os.environ["JWT_SECRET"] = "test-secret-key-for-testing-only-not-real"

    token = create_access_token("user-123")
    assert token

    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"


def test_jwt_extract_user_id():
    import os
    os.environ["JWT_SECRET"] = "test-secret-key-for-testing-only-not-real"

    token = create_access_token("user-456")
    user_id = extract_user_id(token)
    assert user_id == "user-456"


# ============================================================
# IOC Extraction Tests
# ============================================================

def test_triage_extract_iocs():
    """Test IOC extraction (calls static logic, no LLM needed)."""
    from app.agents.triage_agent import _IP_PATTERN, _DOMAIN_PATTERN, _SHA256_PATTERN, _PRIVATE_RANGES

    text = """
    Suspicious connection from 185.220.101.47 to internal server.
    Domain: malicious-domain.ru contacted at 14:32
    File hash: 5f4dcc3b5aa765d61d8327deb882cf99 detected
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """
    ips = _IP_PATTERN.findall(text)
    public_ips = [ip for ip in ips if not any(p.match(ip) for p in _PRIVATE_RANGES)]
    domains = _DOMAIN_PATTERN.findall(text)

    assert "185.220.101.47" in public_ips
    assert any("malicious-domain" in d for d in domains)


def test_triage_excludes_private_ips():
    from app.agents.triage_agent import _IP_PATTERN, _PRIVATE_RANGES
    text = "Connection from 192.168.1.100 and 10.0.0.1 and 127.0.0.1"
    ips = _IP_PATTERN.findall(text)
    public_ips = [ip for ip in ips if not any(p.match(ip) for p in _PRIVATE_RANGES)]
    assert "192.168.1.100" not in public_ips
    assert "10.0.0.1" not in public_ips
    assert "127.0.0.1" not in public_ips


# ============================================================
# Secret Detection Tests
# ============================================================

def test_secret_redaction():
    from app.agents.devsecops_agent import _detect_secrets_in_text, _redact_secret

    # Verify redaction logic: shows first 4 + last 4 chars, rest are *
    test_val = "sk-live-abc123def456"
    redacted = _redact_secret(test_val)
    # Should start with first 4, end with last 4, have *s in middle
    assert redacted.startswith(test_val[:4])
    assert redacted.endswith(test_val[-4:])
    assert "****" in redacted
    assert test_val not in redacted  # Full secret must never appear

    # Test detection
    code = 'API_KEY = "sk-live-abc123def456ghi789"'
    findings = _detect_secrets_in_text(code, "config.py")
    assert len(findings) > 0
    for f in findings:
        # The full secret must NEVER appear in findings
        assert "sk-live-abc123def456ghi789" not in f["redacted_value"]
        assert "****" in f["redacted_value"]
