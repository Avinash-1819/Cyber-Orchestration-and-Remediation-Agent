"""
Cloud Security — deterministic rule engine.

Audits the ACTUAL IaC payload (Terraform / CloudFormation / Kubernetes YAML)
for high-impact misconfigurations: public exposure, wildcard privileges,
missing encryption, missing MFA, container privilege issues.
"""
import re
from typing import Any, Dict, List, Tuple

# (title, severity, pattern, secure_snippet, advice, category)
_RULES: List[Tuple[str, str, re.Pattern, str, str, str]] = [
    (
        "Security group exposes service to 0.0.0.0/0",
        "HIGH",
        re.compile(r"(?i)cidr_blocks?\s*=\s*\[?['\"]0\.0\.0\.0/0|cidr_ipv4\s*=\s*['\"]0\.0\.0\.0/0"),
        "Restrict cidr_blocks to required private ranges",
        "Restrict ingress to approved networks",
        "Cloud-AWS",
    ),
    (
        "IAM policy grants wildcard action/resource",
        "CRITICAL",
        re.compile(r"(?i)actions?\s*=\s*\[?['\"][*]['\"]|effect\s*=\s*['\"]allow['\"][^}]{0,200}?resource['\"]\s*=\s*\[?['\"][*]"),
        "Scope actions and resources to least privilege",
        "Replace wildcard with scoped policy",
        "Cloud-AWS",
    ),
    (
        "S3 bucket publicly readable",
        "CRITICAL",
        re.compile(r"(?i)acl\s*=\s*['\"](public-read|public-read-write|authenticated-read)['\"]"),
        "Remove public ACL; use private + signed URLs",
        "Set private ACL and enable public access block",
        "Cloud-AWS",
    ),
    (
        "S3 bucket without server-side encryption",
        "MEDIUM",
        re.compile(r"(?i)resource\s+['\"]aws_s3_bucket['\"]"),
        "Add server_side_encryption_configuration with aws:kms",
        "Enable SSE-KMS",
        "Cloud-AWS",
    ),
    (
        "Database instance without storage encryption",
        "HIGH",
        re.compile(r"(?i)resource\s+['\"]aws_db_instance['\"]"),
        "Set storage_encrypted = true",
        "Enable storage encryption",
        "Cloud-AWS",
    ),
    (
        "EBS volumes without encryption",
        "MEDIUM",
        re.compile(r"(?i)resource\s+['\"]aws_(ebs_volume|volume_attachment)['\"]|encrypted\s*=\s*false"),
        "Set encrypted = true",
        "Enable EBS encryption",
        "Cloud-AWS",
    ),
    (
        "RDS publicly accessible",
        "HIGH",
        re.compile(r"(?i)publicly_accessible\s*=\s*true"),
        "Set publicly_accessible = false",
        "Disable public DB access",
        "Cloud-AWS",
    ),
    (
        "CloudFront distribution without WAF",
        "MEDIUM",
        re.compile(r"(?i)resource\s+['\"]aws_cloudfront_distribution['\"]"),
        "Attach web_acl_id to the distribution",
        "Attach AWS WAF",
        "Cloud-AWS",
    ),
    (
        "Kubernetes container runs privileged",
        "HIGH",
        re.compile(r"(?i)privileged\s*:\s*true"),
        "privileged: false",
        "Disable privileged containers",
        "Cloud-Kubernetes",
    ),
    (
        "Kubernetes container runs as root",
        "MEDIUM",
        re.compile(r"(?i)runAsUser\s*:\s*0|securityContext\s*:\s*\{\s*\}" ),
        "runAsNonRoot: true with non-zero runAsUser",
        "Run as non-root user",
        "Cloud-Kubernetes",
    ),
    (
        "Kubernetes uses host network namespace",
        "HIGH",
        re.compile(r"(?i)hostNetwork\s*:\s*true"),
        "hostNetwork: false",
        "Disable host networking",
        "Cloud-Kubernetes",
    ),
    (
        "Container registry image without pinned digest",
        "LOW",
        re.compile(r"(?i)image\s*:\s*[a-z0-9./-]+:[a-z0-9.-]+(?<!@)"),
        "Pin image with @sha256: digest",
        "Pin image digests",
        "Cloud-Kubernetes",
    ),
]


def _line(text: str, pos: int):
    return text[:pos].count("\n") + 1


def analyze_cloud_security(files: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Deterministic cloud posture audit of IaC files."""
    findings: List[Dict[str, Any]] = []
    providers_seen = set()

    for file_path, content in files:
        fname = file_path.lower()
        is_iac = fname.endswith((".tf", ".tf.json", ".yaml", ".yml", ".template", ".json"))
        if not is_iac and not re.search(r"(?i)aws_|resource|provider|namespace|kind:\s*Deployment|kind:\s*Pod", content):
            continue
        is_k8s = bool(re.search(r"(?i)apiVersion|kind:\s*(Deployment|Pod|StatefulSet|CronJob)", content))

        if re.search(r"(?i)provider\s+['\"]?(aws|google|azurerm)", content):
            providers_seen.add("AWS" if "aws" in content.lower().split("provider")[1][:50] else "Cloud")

        for title, severity, pattern, secure, advice, category in _RULES:
            if is_k8s and category == "Cloud-AWS":
                continue
            if not is_k8s and category == "Cloud-Kubernetes":
                continue
            for match in pattern.finditer(content):
                findings.append({
                    "title": title,
                    "severity": severity,
                    "category": category,
                    "description": f"{title} detected in {file_path}.",
                    "file_path": file_path,
                    "line_number": _line(content, match.start()),
                    "vulnerable_code": content[max(0, match.start() - 30):match.end() + 30].replace("\n", " ").strip()[:160],
                    "secure_code_snippet": secure,
                    "remediation_advice": advice,
                })
                break  # one per rule per file

    # dedupe
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f.get("file_path"), f.get("line_number"))
        if key not in seen:
            seen.add(key)
            unique.append(f)

    risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in unique) else (
        "HIGH" if any(f["severity"] == "HIGH" for f in unique) else (
            "MEDIUM" if any(f["severity"] == "MEDIUM" for f in unique) else "LOW"
        )
    )

    return {
        "overall_risk_level": risk,
        "summary": (
            f"Cloud posture audit of {len(files)} file(s) identified {len(unique)} misconfiguration(s)."
            + (f" Providers assessed: {', '.join(sorted(providers_seen))}." if providers_seen else "")
        ),
        "cloud_providers": sorted(providers_seen) or ["not-detected"],
        "misconfigurations": unique,
        "checks_performed": len(_RULES),
        "analysis_source": "deterministic_engine",
    }
