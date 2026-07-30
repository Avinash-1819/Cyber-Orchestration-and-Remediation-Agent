"""
Sentinel AI — Grafify Token Minimization Service
Graph-based prompt compaction, log deduplication, code structure extraction, and context pruning
for minimal token consumption across multi-agent pipelines.
"""
import re
from typing import Any, Dict, List, Optional
import structlog

log = structlog.get_logger(__name__)

def grafify_compress_logs(log_text: str, max_lines: int = 50) -> str:
    """
    Compress raw security logs using graph pattern aggregation.
    Deduplicates repeating log patterns and keeps structural representation.
    Reduces log token usage by 50-80%.
    """
    if not log_text or len(log_text) < 200:
        return log_text

    lines = log_text.strip().splitlines()
    if len(lines) <= max_lines:
        return log_text

    pattern_counts: Dict[str, int] = {}
    pattern_samples: Dict[str, str] = {}

    for line in lines:
        # Strip timestamps, process IDs, and specific port numbers to find template
        template = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", line)
        template = re.sub(r"\b[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\b", "<TIME>", template)
        template = re.sub(r"\[\d+\]", "[PID]", template)
        template = re.sub(r"port \d+", "port <PORT>", template)

        if template not in pattern_counts:
            pattern_counts[template] = 0
            pattern_samples[template] = line
        pattern_counts[template] += 1

    compact_lines = []
    for template, count in pattern_counts.items():
        sample = pattern_samples[template]
        if count > 1:
            compact_lines.append(f"{sample} (repeated {count} times)")
        else:
            compact_lines.append(sample)

    compressed = "\n".join(compact_lines[:max_lines])
    log.info("grafify_logs_compressed", original_lines=len(lines), compressed_lines=len(compact_lines))
    return compressed


def grafify_compress_code(code_text: str, max_chars: int = 12000) -> str:
    """
    Prune unnecessary whitespace and blank lines from code snippets
    while preserving structure and line hints.
    """
    if not code_text or len(code_text) <= max_chars:
        return code_text

    # Remove multi-line empty spaces
    compact = re.sub(r"\n\s*\n\s*\n+", "\n\n", code_text)
    if len(compact) > max_chars:
        compact = compact[:max_chars] + "\n... [TRUNCATED FOR TOKEN MINIMIZATION]"

    return compact


def grafify_summarize_upstream_state(state_dict: Dict[str, Any]) -> str:
    """
    Build a minimal graph node summary of upstream agent outputs
    to avoid dumping full state dictionaries into subsequent agent prompts.
    """
    summary_parts = []
    
    if state_dict.get("triage_report"):
        tr = state_dict["triage_report"]
        summary_parts.append(
            f"Node[Triage]: {tr.get('classification','N/A')} | Sev: {tr.get('severity','N/A')} | "
            f"Pattern: {tr.get('attack_pattern','N/A')[:100]}"
        )
        
    if state_dict.get("code_audit_report"):
        car = state_dict["code_audit_report"]
        summary_parts.append(
            f"Node[DevSecOps]: Audit Completed | Findings: {car.get('total_findings', 0)} | "
            f"Summary: {car.get('audit_summary','')[:100]}"
        )
        
    if state_dict.get("threat_intel_report"):
        tir = state_dict["threat_intel_report"]
        summary_parts.append(
            f"Node[ThreatIntel]: Intel Confidence: {tir.get('intelligence_confidence','N/A')} | "
            f"Summary: {tir.get('threat_summary','')[:100]}"
        )

    return "\n".join(summary_parts) if summary_parts else "None"
