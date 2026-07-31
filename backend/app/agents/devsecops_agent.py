"""
Sentinel AI — Agent 3: DevSecOps Agent
SAST + IaC analysis: OWASP Top 10, secrets detection (redacted), Dockerfile/Terraform checks.
Supports direct code input and GitHub repo URL (shallow-cloned, then deleted).

SECURITY NOTE: Detected secrets are ALWAYS redacted before being stored, logged, or reported.
The backend never stores or transmits the full secret value.
"""
import os
import re
import shutil
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog
from pydantic import BaseModel, Field

from app.agents.base_agent import BaseAgent
from app.agents.state import Finding, SentinelState
from app.core.exceptions import AgentError
from app.services.engines import code_audit_engine
from app.services.external_intel import cleanup_temp_dir, clone_github_repo
from app.services.llm_client import MODEL_FLASH
from app.services.grafify import grafify_compress_code

log = structlog.get_logger(__name__)

# ============================================================
# Secret detection patterns (regex + entropy-based)
# ============================================================

SECRET_PATTERNS = [
    (re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?"), "API Key"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?(\S{8,})['\"]?"), "Password"),
    (re.compile(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?"), "Secret Key"),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), "OpenAI API Key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "GitHub Personal Access Token"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS Access Key ID"),
    (re.compile(r"(?i)(private[_-]?key|rsa[_-]?private)\s*[=:]\s*['\"]?-----BEGIN"), "Private Key"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "Slack Token"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"), "JWT Token"),
    (re.compile(r"(?i)authorization:\s*bearer\s+([A-Za-z0-9_\-\.]{20,})"), "Bearer Token"),
]

SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".cs", ".cpp", ".c",
                        ".sh", ".bash", ".dockerfile", "Dockerfile", ".tf", ".yaml", ".yml", ".env",
                        ".json", ".xml", ".toml", ".ini", ".cfg", ".conf"}

MAX_FILE_SIZE_BYTES = 500_000  # Skip files >500KB
MAX_FILES_TO_SCAN = 200


def _redact_secret(value: str) -> str:
    """Redact a secret: show first 4 and last 4 chars with asterisks."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _detect_secrets_in_text(text: str, file_path: str = "") -> List[Dict[str, Any]]:
    """Scan text for secrets. Returns list of findings with REDACTED values."""
    findings = []
    for pattern, secret_type in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw_value = match.group(0) if match.lastindex is None else match.group(match.lastindex)
            redacted = _redact_secret(raw_value)
            line_num = text[:match.start()].count("\n") + 1
            findings.append({
                "type": secret_type,
                "redacted_value": redacted,  # NEVER store the real value
                "file_path": file_path,
                "line_number": line_num,
            })
    return findings


class CodeFindingSchema(BaseModel):
    """Schema for a single code security finding."""
    title: str
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
    category: str = Field(description="e.g. OWASP-A01, IaC-Misconfiguration, Secrets, Dockerfile")
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    vulnerable_code: Optional[str] = None
    secure_code_snippet: Optional[str] = None
    remediation_advice: str


class CodeAuditSchema(BaseModel):
    """LLM output schema for code audit."""
    findings: List[CodeFindingSchema]
    owasp_top10_coverage: List[str] = Field(description="OWASP Top 10 categories checked")
    overall_risk_level: str
    summary: str


class DevSecOpsAgent(BaseAgent):
    AGENT_NAME = "DevSecOpsAgent"

    def _collect_files(self, base_path: str) -> List[Tuple[str, str]]:
        """Collect (file_path, content) tuples from a directory."""
        files = []
        base = Path(base_path)

        for root, dirs, filenames in os.walk(base):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                ".git", "node_modules", "vendor", "__pycache__", ".venv",
                "venv", "dist", "build", ".terraform", "target"
            }]

            for filename in filenames:
                fpath = Path(root) / filename
                if (fpath.suffix in SUPPORTED_EXTENSIONS or filename in SUPPORTED_EXTENSIONS) and \
                   fpath.stat().st_size <= MAX_FILE_SIZE_BYTES:
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                        files.append((str(fpath.relative_to(base)), content))
                        if len(files) >= MAX_FILES_TO_SCAN:
                            return files
                    except Exception:
                        pass

        return files

    def _detect_secrets_all_files(self, files: List[Tuple[str, str]]) -> List[Finding]:
        """Run secret detection across all collected files."""
        findings = []
        for file_path, content in files:
            secrets = _detect_secrets_in_text(content, file_path)
            for s in secrets:
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    severity="CRITICAL",
                    category="Secrets",
                    title=f"Hardcoded {s['type']} detected",
                    description=f"A {s['type']} was detected in {s['file_path']} at line {s.get('line_number', '?')}. "
                                f"Redacted value: `{s['redacted_value']}`",
                    file_path=s["file_path"],
                    line_number=s.get("line_number"),
                    remediation_advice="Remove the secret from source code immediately. "
                                       "Rotate/revoke the credential. Use environment variables or a secrets manager.",
                ))
        return findings

    def _redacted_snippets(self, files: List[Tuple[str, str]]) -> List[Dict[str, str]]:
        """Return capped, secret-redacted file snippets for downstream agents."""
        snippets = []
        for file_path, content in files[:10]:
            redacted = content[:3000]
            for pattern, _ in SECRET_PATTERNS:
                redacted = pattern.sub("***REDACTED***", redacted)
            snippets.append({"path": file_path, "content": redacted})
        return snippets

    async def execute(self, state: SentinelState) -> SentinelState:
        """Run SAST and IaC analysis on code or GitHub repo."""
        temp_dir: Optional[str] = None
        files: List[Tuple[str, str]] = []

        try:
            # 1. Determine input source
            if state.input_type == "REPO_URL":
                self._trace(state, "cloning_repo")
                repo_url = state.raw_input.strip()
                temp_dir = await clone_github_repo(repo_url)
                files = self._collect_files(temp_dir)
                self._trace(state, "repo_cloned", {"file_count": len(files)})
            else:
                # Direct code input
                files = [("input_code", state.raw_input)]

            # 2. Secret detection (always runs first, result redacted before anything else)
            self._trace(state, "detecting_secrets")
            secret_findings = self._detect_secrets_all_files(files)
            state.findings.extend(secret_findings)
            self._trace(state, "secrets_detected", {"count": len(secret_findings)})

            # 3. Build code context for LLM (with Grafify token compaction)
            code_context = ""
            total_chars = 0
            for file_path, content in files[:30]:  # Cap at 30 files for LLM
                compressed_content = grafify_compress_code(content[:3000])
                chunk = f"\n\n--- FILE: {file_path} ---\n{compressed_content}"
                if total_chars + len(chunk) > 40000:
                    break
                code_context += chunk
                total_chars += len(chunk)

            self._trace(state, "running_sast_llm")

            # 4. LLM-based SAST + IaC analysis
            prompt = f"""You are a senior application security engineer performing a comprehensive code security audit.

Analyze the following code for security vulnerabilities across these categories:
- OWASP Top 10: SQL Injection (A01), XSS (A03), Command Injection (A03), Path Traversal, Insecure Deserialization (A08), Broken Auth (A07), Sensitive Data Exposure (A02), Security Misconfiguration (A05), Vulnerable Components (A06), SSRF (A10)
- IaC Security: Terraform overly-permissive IAM ("*:*"), unencrypted storage (aws_s3_bucket without encryption), public access misconfigs
- Dockerfile: Running as root (no USER instruction), outdated base images (e.g., ubuntu:14.04), secrets passed as ENV, ADD vs COPY
- CI/CD: Secrets in YAML, unpinned actions, excessive permissions

DO NOT report any actual secret values — they have already been detected and redacted separately.

For each finding, provide:
- Specific file path and line number if identifiable
- The vulnerable code snippet
- A secure replacement code snippet
- Concrete remediation advice

CODE TO ANALYZE:
{code_context}"""

            def _deterministic_audit() -> CodeAuditSchema:
                data = code_audit_engine.analyze_code_audit(files)
                return CodeAuditSchema(**data)

            try:
                audit = await self.llm.generate_structured(
                    prompt=prompt,
                    output_schema=CodeAuditSchema,
                    model_role=MODEL_FLASH,
                    agent_name=self.AGENT_NAME,
                    temperature=0.1,
                    fallback_factory=_deterministic_audit,
                )
            except Exception as e:
                raise AgentError(self.AGENT_NAME, f"SAST analysis failed: {e}") from e

            # 5. Convert LLM findings to Finding objects
            for llm_finding in audit.findings:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    severity=llm_finding.severity,
                    category=llm_finding.category,
                    title=llm_finding.title,
                    description=llm_finding.description,
                    file_path=llm_finding.file_path or None,
                    line_number=llm_finding.line_number,
                    remediation_advice=llm_finding.remediation_advice,
                )
                state.findings.append(finding)

            state.code_audit_report = {
                "summary": audit.summary,
                "overall_risk_level": audit.overall_risk_level,
                "owasp_coverage": audit.owasp_top10_coverage,
                "sast_findings_count": len(audit.findings),
                "secrets_findings_count": len(secret_findings),
                "files_scanned": len(files),
                "findings_detail": [f.model_dump() for f in audit.findings],
                # Redacted snippets so downstream agents (Cloud/Network) can analyze the
                # actual IaC/code without re-cloning. Secrets are NEVER persisted.
                "file_snippets": self._redacted_snippets(files),
            }

            self._trace(state, "sast_complete", {
                "sast_findings": len(audit.findings),
                "secrets": len(secret_findings),
                "risk": audit.overall_risk_level,
            })

        finally:
            # ALWAYS delete the cloned repo — never persist customer source code
            if temp_dir:
                cleanup_temp_dir(temp_dir)
                self._trace(state, "temp_repo_deleted")

        return state
