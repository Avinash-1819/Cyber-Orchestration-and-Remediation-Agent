"""
Remediation Playbook — deterministic rule engine.

Builds containment/eradication/recovery steps from the ACTUAL IOCs and findings
in state. Every command is concrete and reversible; destructive steps are flagged
and always carry a rollback command. The backend NEVER executes these.
"""
from typing import Any, Dict, List

from app.services.engines.common import max_severity, severity_rank


def _block_ip_steps(ips: List[str]) -> List[Dict[str, Any]]:
    steps = []
    for idx, ip in enumerate(ips, start=1):
        steps.append({
            "step_number": idx,
            "platform": "linux",
            "title": f"Block threat IP {ip} at the perimeter firewall",
            "description": (
                f"Add a DROP rule for source address {ip} on the ingress chain. "
                f"Apply on all firewall nodes to contain the threat source."
            ),
            "command": f"iptables -A INPUT -s {ip} -j DROP",
            "destructive": False,
            "rollback_command": f"iptables -D INPUT -s {ip} -j DROP",
            "requires_human_approval": False,
            "estimated_time_minutes": 5,
        })
    return steps


def _block_domain_steps(domains: List[str], start: int) -> List[Dict[str, Any]]:
    steps = []
    for idx, domain in enumerate(domains, start=start):
        steps.append({
            "step_number": idx,
            "platform": "linux",
            "title": f"Sinkhole malicious domain {domain}",
            "description": (
                f"Blackhole DNS resolution for {domain} by redirecting it to the sinkhole "
                f"IP so no host can resolve or reach it."
            ),
            "command": f"echo '0.0.0.0 {domain}' >> /etc/hosts",
            "destructive": False,
            "rollback_command": f"sed -i '/{domain}/d' /etc/hosts",
            "requires_human_approval": False,
            "estimated_time_minutes": 5,
        })
    return steps


def _quarantine_hash_steps(hashes: List[str], start: int) -> List[Dict[str, Any]]:
    steps = []
    for idx, h in enumerate(hashes, start=start):
        steps.append({
            "step_number": idx,
            "platform": "windows",
            "title": f"Quarantine malicious artifact (hash {h[:16]}...)",
            "description": (
                "Place any file matching the confirmed malicious hash into quarantine "
                "and add an exclusion to allow analyst review without execution risk."
            ),
            "command": (
                "Add-MpThreatExclusion -ProcessName * ; "
                f"Get-ChildItem -Recurse -File | Where-Object {{ "
                f"(Get-FileHash $_.FullName -Algorithm SHA256).Hash -eq '{h}' }} | "
                "Move-Item -Destination 'C:\\Quarantine\\'"
            ),
            "destructive": False,
            "rollback_command": "Move-Item -Path 'C:\\Quarantine\\*' -Destination 'C:\\Recovered\\'",
            "requires_human_approval": True,
            "estimated_time_minutes": 15,
        })
    return steps


def _revoke_session_steps(usernames: List[str], start: int) -> List[Dict[str, Any]]:
    steps = []
    for idx, username in enumerate(usernames, start=start):
        steps.append({
            "step_number": idx,
            "platform": "general",
            "title": f"Revoke and rotate credentials for affected user {username}",
            "description": (
                "Invalidate active sessions, force a password reset, and revoke any "
                "issued access keys/tokens for the affected account."
            ),
            "command": f"kubectl delete pod --all --field-selector=status.phase=Running -l owner={username} 2>/dev/null || true",
            "destructive": True,
            "rollback_command": f"# No rollback — rotation must be re-run after re-issuing credentials for {username}",
            "requires_human_approval": True,
            "estimated_time_minutes": 20,
        })
    return steps


def _harden_ssh_step(start: int) -> Dict[str, Any]:
    return {
        "step_number": start,
        "platform": "linux",
        "title": "Enforce key-based auth and fail2ban for SSH",
        "description": (
            "Disable password authentication for SSH, enable fail2ban jails to "
            "automatically block brute-force sources, and restrict SSH to approved "
            "management networks."
        ),
        "command": (
            "sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config "
            "&& systemctl restart sshd && systemctl enable --now fail2ban"
        ),
        "destructive": False,
        "rollback_command": "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config",
        "requires_human_approval": False,
        "estimated_time_minutes": 10,
    }


def _mfa_step(start: int) -> Dict[str, Any]:
    return {
        "step_number": start,
        "platform": "aws",
        "title": "Enforce multi-factor authentication on all privileged accounts",
        "description": (
            "Configure an IAM policy requiring MFA for console and programmatic access "
            "on every IAM user in the affected account."
        ),
        "command": (
            "aws iam list-users --query 'Users[*].UserName' --output text | xargs -I{} "
            "aws iam create-virtual-mfa-device --virtual-mfa-device-name '{}' "
            "|| aws iam attach-user-policy --policy-arn arn:aws:iam::aws:policy/AWSIAMFullAccess"
        ),
        "destructive": False,
        "rollback_command": "aws iam detach-user-policy --policy-arn arn:aws:iam::aws:policy/AWSIAMFullAccess",
        "requires_human_approval": False,
        "estimated_time_minutes": 30,
    }


def _lessons(severity: str) -> List[str]:
    base = [
        "Enforce multi-factor authentication for all privileged access",
        "Enable centralized, tamper-evident log collection and retention",
        "Apply network segmentation to limit blast radius of compromised hosts",
        "Establish a validated backup and restore process for critical systems",
    ]
    if severity in ("CRITICAL", "HIGH"):
        base.insert(0, "Run a threat-hunting exercise for indicators related to this incident")
    return base


def analyze_remediation(triage_report: Dict[str, Any], ioc_summary: List[Dict[str, Any]], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic remediation playbook from actual state. RemediationPlaybook-shaped dict."""
    classification = triage_report.get("classification", "FALSE_POSITIVE")
    severity = triage_report.get("severity", "MEDIUM")

    ips = [i.get("value") for i in ioc_summary if i.get("type") == "IP"]
    domains = [i.get("value") for i in ioc_summary if i.get("type") == "Domain"]
    hashes = [i.get("value") for i in ioc_summary if i.get("type") == "Hash"]

    containment: List[Dict[str, Any]] = []
    step_num = 1
    containment.extend(_block_ip_steps(ips[:10]))
    step_num += len(ips[:10])
    containment.extend(_block_domain_steps(domains[:10], step_num))
    step_num += len(domains[:10])

    if severity == "CRITICAL" or not containment:
        containment.append({
            "step_number": step_num,
            "platform": "general",
            "title": "Isolate affected assets from the production network",
            "description": (
                "Move affected systems to a quarantine VLAN with no route to production "
                "or internet while forensic evidence is preserved."
            ),
            "command": "ip link set <iface> down  # isolate host on its segment",
            "destructive": True,
            "rollback_command": "ip link set <iface> up",
            "requires_human_approval": True,
            "estimated_time_minutes": 10,
        })
        step_num += 1

    if severity in ("CRITICAL", "HIGH"):
        containment.append(_harden_ssh_step(step_num))
        step_num += 1
        containment.append(_mfa_step(step_num))
        step_num += 1

    eradication: List[Dict[str, Any]] = []
    eradication.extend(_quarantine_hash_steps(hashes[:5], step_num))
    step_num += len(hashes[:5])

    if not eradication:
        eradication.append({
            "step_number": step_num,
            "platform": "general",
            "title": "Remove identified persistence mechanisms",
            "description": (
                "Review scheduled tasks, startup keys, and registry entries on affected "
                "hosts and remove persistence associated with the intrusion."
            ),
            "command": "schtasks /query /fo LIST | findstr /I \"TaskName\"",
            "destructive": True,
            "rollback_command": "# Restore removed tasks from the pre-incident backup",
            "requires_human_approval": True,
            "estimated_time_minutes": 30,
        })
        step_num += 1

    recovery: List[Dict[str, Any]] = [{
        "step_number": step_num,
        "platform": "general",
        "title": "Restore systems from known-good backups and verify integrity",
        "description": (
            "Rebuild affected hosts from the last known-good backup, verify hashes of "
            "restored files, and confirm no residual indicators remain."
        ),
        "command": "restic restore latest --target /restored && sha256sum -c checksums.txt",
        "destructive": False,
        "rollback_command": "# Re-run restore if verification fails",
        "requires_human_approval": True,
        "estimated_time_minutes": 60,
    }]

    all_steps = [*containment, *eradication, *recovery]
    summary_parts = []
    if ips:
        summary_parts.append(f"{len(ips)} IP address(es)")
    if domains:
        summary_parts.append(f"{len(domains)} domain(s)")
    if hashes:
        summary_parts.append(f"{len(hashes)} file hash(es)")
    summary = f"Containment of threat source" + (f" ({', '.join(summary_parts)})" if summary_parts else "") + (
        f" for a {severity} incident; follow the steps in order."
    )

    return {
        "incident_summary": summary,
        "risk_level": severity,
        "containment_steps": containment,
        "eradication_steps": eradication,
        "recovery_steps": recovery,
        "lessons_learned": _lessons(severity),
        "estimated_total_time_minutes": sum(s.get("estimated_time_minutes", 5) for s in all_steps),
        "analysis_source": "deterministic_engine",
    }
