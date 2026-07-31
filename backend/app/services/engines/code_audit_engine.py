"""
DevSecOps / SAST — deterministic rule engine.

Performs real static analysis over the actual code payload:
secrets, injection, unsafe APIs, IaC misconfigs, Dockerfile issues.
Every finding references the actual file/line where available.
"""
import re
from typing import Any, Dict, List, Optional, Tuple

# ---- Secret patterns (mirror devsecops_agent) ----
_SECRET_PATTERNS = [
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


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _line(text: str, pos: int) -> Optional[int]:
    return text[:pos].count("\n") + 1


def _check_secrets(text: str, file_path: str) -> List[Dict[str, Any]]:
    findings = []
    for pattern, secret_type in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            raw = match.group(match.lastindex) if match.lastindex else match.group(0)
            findings.append({
                "title": f"Hardcoded {secret_type} detected",
                "severity": "CRITICAL",
                "category": "Secrets",
                "description": (
                    f"A {secret_type} was found in source. Redacted value: `{_redact(raw)}`. "
                    "Exposing credentials in code enables account takeover and lateral movement."
                ),
                "file_path": file_path,
                "line_number": _line(text, match.start()),
                "vulnerable_code": _redact(raw),
                "secure_code_snippet": "Use a secrets manager / environment variable instead.",
                "remediation_advice": "Remove the secret, rotate/revoke it, and load it from a secure store at runtime.",
            })
    return findings


# ---- Injection / unsafe API checks ----
_INJECTION_PATTERNS = [
    ("SQL Injection", "HIGH", "A03",
     re.compile(r"(?i)(execute|executemany|cursor\.execut|\.query\()\s*\(\s*f['\"]|(\"select|'select|`select).*%(.*)%"),
     "Dynamic SQL built by string formatting/interpolation enables injection."),
    ("Command Injection", "CRITICAL", "A03",
     re.compile(r"(?i)(os\.system|subprocess\.(run|popen|call)|Popen)\s*\([^)]*shell\s*=\s*True|subprocess\.(run|popen|call)\s*\(f['\"]"),
     "Command execution with shell=True or interpolated input allows arbitrary OS commands."),
    ("Arbitrary Code Execution", "CRITICAL", "A03",
     re.compile(r"(?i)\b(eval|exec)\s*\(|compile\s*\(.*,\s*'exec'"),
     "eval/exec of dynamic content executes arbitrary code."),
    ("Path Traversal", "HIGH", "A01",
     re.compile(r"(?i)open\s*\(f['\"]|os\.path\.join\s*\([^)]*request|send_file\s*\([^)]*user"),
     "User-controlled values concatenated into file paths enable directory traversal."),
    ("SSRF", "HIGH", "A10",
     re.compile(r"(?i)(requests\.get|requests\.post|urlopen|httpx\.Client|aiohttp)\s*\([^)]*(url|uri|target|host)\b"),
     "Client-supplied URLs fetched without allow-listing can target internal services (SSRF)."),
    ("Insecure Deserialization", "HIGH", "A08",
     re.compile(r"(?i)(pickle\.loads?|yaml\.load\s*\(|marshal\.loads|shelve\.open)"),
     "Unsafe deserialization of untrusted data can lead to RCE."),
    ("Weak Cryptography", "MEDIUM", "A02",
     re.compile(r"(?i)(hashlib\.md5|hashlib\.sha1|DES3|DES\.|blowfish|md5\()"),
     "Weak hash/cipher algorithms weaken integrity and confidentiality guarantees."),
]

_OIDC_INSECURE = re.compile(r"(?i)(requests|urllib|httpx).*(verify\s*=\s*False|verify=False)")
_HARDCODED_CRED_USE = re.compile(r"(?i)(password|passwd|secret|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]")


def _check_code_flaws(text: str, file_path: str) -> List[Dict[str, Any]]:
    findings = []
    for title, severity, category, pattern, advice in _INJECTION_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "title": title,
                "severity": severity,
                "category": f"OWASP-{category}",
                "description": advice,
                "file_path": file_path,
                "line_number": _line(text, match.start()),
                "vulnerable_code": text[max(0, match.start() - 40):match.end() + 40].replace("\n", " ").strip(),
                "secure_code_snippet": "Parameterize queries / avoid shell=True / validate and allow-list inputs.",
                "remediation_advice": advice,
            })
            break  # one per pattern per file
    return findings


# ---- Dockerfile checks ----
def _check_dockerfile(text: str, file_path: str) -> List[Dict[str, Any]]:
    findings = []
    from_re = re.search(r"(?im)^FROM\s+(\S+)", text)
    if from_re:
        image = from_re.group(1)
        if any(bad in image.lower() for bad in ("14.04", "16.04", "18.04", "20.04", "8", "9", "10", "11", "latest")):
            findings.append({
                "title": "Outdated or untagged base image",
                "severity": "HIGH",
                "category": "Dockerfile",
                "description": (
                    f"Base image `{image}` is outdated or uses a floating tag. "
                    "Outdated images carry known vulnerabilities."
                ),
                "file_path": file_path,
                "line_number": _line(text, from_re.start()),
                "vulnerable_code": from_re.group(0),
                "secure_code_snippet": "Pin a patched, versioned base image (e.g. `FROM python:3.12-slim@sha256:...`).",
                "remediation_advice": "Use a pinned, regularly-updated base image and add a vulnerability scan stage.",
            })
    if not re.search(r"(?im)^USER\s+", text):
        findings.append({
            "title": "Container runs as root",
            "severity": "MEDIUM",
            "category": "Dockerfile",
            "description": "No USER instruction found — the container process will run with root privileges.",
            "file_path": file_path,
            "line_number": None,
            "vulnerable_code": "(missing USER instruction)",
            "secure_code_snippet": "Add `USER 10001` (non-root) before the CMD/ENTRYPOINT.",
            "remediation_advice": "Run the container as a non-root user and drop all capabilities.",
        })
    return findings


# ---- Terraform / IaC checks ----
_IAM_WILDCARD = re.compile(r"(?i)actions?\s*=\s*\[?['\"][*]['\"]|effect\s*=\s*['\"]allow['\"][^}]*resource['\"]\s*=\s*\[?['\"][*]")
_SG_ANYWHERE = re.compile(r"(?i)(cidr_blocks|cidr_ipv4)\s*=\s*\[?['\"]0\.0\.0\.0/0")
_S3_NO_ENCRYPTION = re.compile(r"(?i)resource\s+\"aws_s3_bucket\"")
_S3_PUBLIC_ACL = re.compile(r"(?i)(acl\s*=\s*['\"](public-read|public-read-write)['\"])")
_DB_NO_ENCRYPTION = re.compile(r"(?i)resource\s+\"aws_db_instance\"")
_EBS_NO_ENCRYPTION = re.compile(r"(?i)resource\s+\"aws_(ebs_volume|launch_configuration|volume_attachment)\"")
_PUBLIC_BLOCK_MISSING = re.compile(r"(?i)aws_s3_bucket_public_access_block")
_MFA_MISSING = re.compile(r"(?i)resource\s+\"aws_iam_user\"")
_GKE_MASTER_AUTH = re.compile(r"(?i)resource\s+\"aws_eks_cluster\"")


def _check_terraform(text: str, file_path: str) -> List[Dict[str, Any]]:
    findings = []
    for match in _IAM_WILDCARD.finditer(text):
        findings.append({
            "title": "Overly-permissive IAM policy (* action or * resource)",
            "severity": "CRITICAL",
            "category": "IaC-Misconfiguration",
            "description": "An IAM policy grants wildcard actions/resources, allowing unrestricted access.",
            "file_path": file_path,
            "line_number": _line(text, match.start()),
            "vulnerable_code": match.group(0),
            "secure_code_snippet": "Scope actions and resources to the minimum required set.",
            "remediation_advice": "Replace wildcard privileges with least-privilege scoped policies.",
        })
    for match in _SG_ANYWHERE.finditer(text):
        findings.append({
            "title": "Security group allows ingress from 0.0.0.0/0",
            "severity": "HIGH",
            "category": "IaC-Misconfiguration",
            "description": "An AWS security group rule exposes a service to the entire internet.",
            "file_path": file_path,
            "line_number": _line(text, match.start()),
            "vulnerable_code": match.group(0),
            "secure_code_snippet": "Restrict cidr_blocks to the required network segments.",
            "remediation_advice": "Restrict ingress to approved source networks; use security groups per service.",
        })
    if _S3_NO_ENCRYPTION.search(text) and not re.search(r"(?i)server_side_encryption_configuration", text):
        findings.append({
            "title": "S3 bucket without server-side encryption",
            "severity": "MEDIUM",
            "category": "IaC-Misconfiguration",
            "description": "S3 bucket declared without server-side encryption configuration.",
            "file_path": file_path,
            "line_number": None,
            "vulnerable_code": "(aws_s3_bucket without server_side_encryption_configuration)",
            "secure_code_snippet": "Add server_side_encryption_configuration with aws:kms.",
            "remediation_advice": "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets.",
        })
    if _S3_PUBLIC_ACL.search(text):
        for match in _S3_PUBLIC_ACL.finditer(text):
            findings.append({
                "title": "S3 bucket publicly readable/writable",
                "severity": "CRITICAL",
                "category": "IaC-Misconfiguration",
                "description": "Bucket ACL is set to a public policy, exposing objects to the internet.",
                "file_path": file_path,
                "line_number": _line(text, match.start()),
                "vulnerable_code": match.group(1),
                "secure_code_snippet": "Remove public ACLs and use private buckets + signed URLs.",
                "remediation_advice": "Remove public ACL and add a public_access_block.",
            })
    if _DB_NO_ENCRYPTION.search(text) and not re.search(r"(?i)storage_encrypted\s*=\s*true", text):
        findings.append({
            "title": "RDS instance without storage encryption",
            "severity": "HIGH",
            "category": "IaC-Misconfiguration",
            "description": "Database instance declared without storage_encrypted = true.",
            "file_path": file_path,
            "line_number": None,
            "vulnerable_code": "(aws_db_instance without storage_encrypted)",
            "secure_code_snippet": "Set `storage_encrypted = true` and reference a KMS key.",
            "remediation_advice": "Enable storage encryption at rest for all database instances.",
        })
    if _PUBLIC_BLOCK_MISSING.search(text):
        for match in _PUBLIC_BLOCK_MISSING.finditer(text):
            if _S3_NO_ENCRYPTION.search(text):
                continue
    return findings


def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f.get("file_path"), f.get("line_number"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze_code_audit(files: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Deterministic SAST + IaC + secrets audit. Returns CodeAuditSchema-shaped dict."""
    findings: List[Dict[str, Any]] = []
    owasp_seen = set()
    total_chars = 0

    for file_path, content in files:
        total_chars += len(content)
        if len(content) > 500_000:
            continue
        findings.extend(_check_secrets(content, file_path))
        findings.extend(_check_code_flaws(content, file_path))

        fname = file_path.lower()
        if fname.endswith(("dockerfile", ".dockerfile")) or "dockerfile" in fname:
            findings.extend(_check_dockerfile(content, file_path))
        if fname.endswith((".tf", ".tf.json", ".template", ".yaml", ".yml")):
            findings.extend(_check_terraform(content, file_path))

    for f in findings:
        if f["category"].startswith("OWASP-"):
            owasp_seen.add(f["category"])

    findings = _dedupe(findings)

    risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else (
        "HIGH" if any(f["severity"] == "HIGH" for f in findings) else (
            "MEDIUM" if any(f["severity"] == "MEDIUM" for f in findings) else "LOW"
        )
    )

    summary = (
        f"Static analysis over {len(files)} file(s) ({total_chars} chars) identified "
        f"{len(findings)} real finding(s). " + (
            f"Highest severity: {risk}."
            if findings else
            "No critical, high, or medium-severity issues were identified by rule-based checks."
        )
    )

    return {
        "findings": findings,
        "owasp_top10_coverage": sorted(owasp_seen),
        "overall_risk_level": risk,
        "summary": summary,
        "analysis_source": "deterministic_engine",
    }
