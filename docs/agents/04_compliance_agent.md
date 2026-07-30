# 📋 Compliance Agent (`ComplianceAgent`)

## Overview
The **Compliance Agent** evaluates findings from upstream agents against global Governance, Risk, and Compliance (GRC) control frameworks.

- **Source Code**: [`backend/app/agents/compliance_agent.py`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/app/agents/compliance_agent.py)
- **Compliance Dataset Directory**: [`backend/data/compliance_mappings/`](file:///home/avinash/.gemini/antigravity/scratch/cyber%20-orchestration/backend/data/compliance_mappings/)
- **Model Used**: `gemini-2.0-flash`

---

## 📜 Supported Framework Datasets (YAML)

1. **ISO 27001:2022** (`iso27001.yaml`): Controls A.5, A.8, A.12 (Vulnerability Management, Access Control, Encryption).
2. **SOC 2 Type II** (`soc2.yaml`): Trust Services Criteria CC6.1, CC6.6, CC6.8, CC7.1.
3. **NIST SP 800-53 Rev 5** (`nist_800_53.yaml`): Control families AC (Access Control), SI (System & Information Integrity), SC (System & Comms Protection).
4. **PCI DSS 4.0** (`pci_dss_4.yaml`): Requirements 2, 3, 6, 8, 10, 11 (Secure Systems, Data Protection, Access Control).

---

## 📊 Compliance Score Calculation

- Computes a overall numerical compliance percentage score (0–100%):
  $$\text{Score} = \max\left(0, 100 - (\text{Critical} \times 25 + \text{High} \times 15 + \text{Medium} \times 5)\right)$$
- Attaches relevant framework control strings to findings (e.g. `["ISO27001:A.12.6", "NIST:SI-2"]`).
- Compiles an **Auditor Evidence Checklist** with pass/fail criteria.
