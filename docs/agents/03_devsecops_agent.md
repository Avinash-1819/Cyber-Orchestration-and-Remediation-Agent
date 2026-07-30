# 🛡️ DevSecOps Agent (`DevSecOpsAgent`)

## Overview
The **DevSecOps Agent** performs Static Application Security Testing (SAST), secret scanning, Dockerfile container auditing, and Infrastructure-as-Code (IaC) Terraform configuration audits.

- **Source Code**: [`backend/app/agents/devsecops_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/devsecops_agent.py)
- **Model Used**: `gemini-2.0-flash`

---

## 🔍 Core Scanning Engine Capabilities

### 1. Regex Secret Detection (Ran locally before LLM submission)
- AWS Access Keys (`AKIA[0-9A-Z]{16}`)
- GitHub Personal Access Tokens (`ghp_[A-Za-z0-9_]{36}`)
- Generic API Keys (`api_key = "..."`)
- JWT Tokens (`eyJ...`)
- **Redaction Guarantee**: All secrets found in code are masked (showing only first 4 and last 4 characters) before sending prompts to the LLM.

### 2. GitHub Repository Cloning (`clone_github_repo`)
- Clones public GitHub URLs asynchronously to temporary sandboxed directories.
- Traverses codebases recursively, filtering supported extensions (`.py`, `.js`, `.ts`, `.java`, `.go`, `.tf`, `Dockerfile`, etc.).

### 3. Dockerfile & Terraform Audits
- Identifies container running as `root`, outdated base images, and embedded `ENV` secrets.
- Identifies overly permissive Terraform security group rules (`0.0.0.0/0`) and public S3 bucket ACLs.

---

## 📄 Output Schema (`CodeAuditSchema`)

```python
class CodeFinding(BaseModel):
    category: str  # OWASP-A01 | Secrets | Dockerfile | Terraform | CodeQuality
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    title: str
    file_path: str
    line_number: Optional[int]
    description: str
    vulnerable_snippet: str
    secure_fix_snippet: str
    remediation_advice: str
```
