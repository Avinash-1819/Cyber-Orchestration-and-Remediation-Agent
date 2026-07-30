# ⚡ Remediation Agent (`RemediationAgent`)

## Overview
The **Remediation Agent** translates incident triage findings into containment playbooks, defensive shell commands, and automated mitigation steps.

- **Source Code**: [`backend/app/agents/remediation_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/remediation_agent.py)
- **Model Used**: `gemini-2.0-flash`

---

## 🛡️ Key Features

1. **Multi-OS / Multi-Environment Command Generation**:
   - Linux Shell (`iptables`, `systemctl`, `ufw`, `pkill`)
   - Windows PowerShell (`Stop-Process`, `New-NetFirewallRule`)
   - Kubernetes (`kubectl Cordon`, `kubectl delete pod`)
   - Cloud IAM (`aws iam revoke-security-group-ingress`)

2. **Human-in-the-Loop Approval Gates (`destructive`)**:
   - Commands that modify production configurations, terminate critical services, or purge data are flagged as `destructive: true`.
   - In the frontend UI, destructive commands trigger a **Destructive Action Modal** requiring the operator to type `"APPROVE"` before copying or executing scripts.

---

## 📄 Output Schema (`RemediationPlanSchema`)

```python
class RemediationAction(BaseModel):
    step_number: int
    action_type: str  # CONTAINMENT | ISOLATION | ERADICATION | RECOVERY
    title: str
    command: str
    is_destructive: bool
    justification: str

class RemediationPlanSchema(BaseModel):
    summary: str
    immediate_containment: List[RemediationAction]
    long_term_hardening: List[str]
```
