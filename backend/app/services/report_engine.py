"""
Sentinel AI — Report Engine
Generates PDF (ReportLab), Markdown, and JSON artifacts from a SentinelState.
All three formats are derived from the same state object — they never drift.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.agents.state import SentinelState
from app.core.config import settings
from app.core.exceptions import ReportGenerationError

log = structlog.get_logger(__name__)

# Sentinel AI color palette (matches frontend)
COLOR_CRITICAL = colors.HexColor("#EF4444")
COLOR_HIGH = colors.HexColor("#F97316")
COLOR_MEDIUM = colors.HexColor("#EAB308")
COLOR_LOW = colors.HexColor("#3B82F6")
COLOR_INFO = colors.HexColor("#6B7280")
COLOR_BG_DARK = colors.HexColor("#0F172A")
COLOR_BG_CARD = colors.HexColor("#1E293B")
COLOR_ACCENT = colors.HexColor("#6366F1")
COLOR_TEXT = colors.HexColor("#F1F5F9")


def _severity_color(severity: str) -> colors.HexColor:
    return {
        "CRITICAL": COLOR_CRITICAL,
        "HIGH": COLOR_HIGH,
        "MEDIUM": COLOR_MEDIUM,
        "LOW": COLOR_LOW,
        "INFORMATIONAL": COLOR_INFO,
    }.get(severity.upper(), COLOR_INFO)


def _ensure_output_dir(session_id: str) -> Path:
    output_dir = Path(settings.REPORTS_OUTPUT_DIR) / session_id
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


# ============================================================
# PDF Report
# ============================================================

def generate_pdf(state: SentinelState) -> str:
    """Generate a PDF report and return the file path."""
    try:
        output_dir = _ensure_output_dir(state.session_id)
        pdf_path = output_dir / "report.pdf"

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        styles = getSampleStyleSheet()
        story = []

        # --- Cover Page ---
        story.extend(_build_cover_page(state, styles))
        story.append(PageBreak())

        # --- Executive Summary ---
        if state.executive_summary:
            story.extend(_build_executive_summary(state, styles))
            story.append(PageBreak())

        # --- Risk Matrix ---
        story.extend(_build_risk_matrix(state, styles))
        story.append(PageBreak())

        # --- Findings Table ---
        if state.findings:
            story.extend(_build_findings_table(state, styles))
            story.append(PageBreak())

        # --- Technical Details ---
        story.extend(_build_technical_details(state, styles))

        doc.build(story)
        log.info("pdf_generated", session_id=state.session_id, path=str(pdf_path))
        return str(pdf_path)

    except Exception as e:
        raise ReportGenerationError(f"PDF generation failed: {e}") from e


def _build_cover_page(state: SentinelState, styles) -> list:
    """Build the report cover page."""
    elements = []

    title_style = ParagraphStyle(
        "CoverTitle", fontSize=28, textColor=COLOR_ACCENT,
        alignment=TA_CENTER, spaceAfter=10, fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle", fontSize=14, textColor=colors.grey,
        alignment=TA_CENTER, spaceBefore=12, spaceAfter=6
    )
    meta_style = ParagraphStyle(
        "CoverMeta", fontSize=11, textColor=colors.black,
        alignment=TA_CENTER, spaceAfter=4
    )
    badge_style = ParagraphStyle(
        "CoverBadge", fontSize=14, textColor=colors.white,
        alignment=TA_CENTER, fontName="Helvetica-Bold"
    )

    elements.append(Spacer(1, 1.5 * cm))
    elements.append(Paragraph("SENTINEL AI", title_style))
    elements.append(Paragraph("Cybersecurity Intelligence & Remediation Report", subtitle_style))
    elements.append(HRFlowable(width="80%", thickness=2, color=COLOR_ACCENT, spaceAfter=15))
    elements.append(Spacer(1, 0.5 * cm))

    summary = state.finding_summary
    overall_risk = "CRITICAL" if summary["CRITICAL"] > 0 else ("HIGH" if summary["HIGH"] > 0 else ("MEDIUM" if summary["MEDIUM"] > 0 else ("LOW" if summary["LOW"] > 0 else "INFORMATIONAL")))

    # Risk Badge
    risk_table = Table([[Paragraph(f"OVERALL RISK LEVEL: {overall_risk}", badge_style)]], colWidths=[12 * cm])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _severity_color(overall_risk)),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 0.8 * cm))

    elements.append(Paragraph(f"Session ID: {state.session_id}", meta_style))
    elements.append(Paragraph(f"Pipeline: {state.pipeline} | Input Type: {state.input_type}", meta_style))
    elements.append(Paragraph(f"Generated: {state.created_at.strftime('%Y-%m-%d %H:%M UTC')}", meta_style))
    elements.append(Spacer(1, 0.8 * cm))

    # Severity summary table
    severity_data = [
        ["Severity", "Count"],
        ["CRITICAL", str(summary["CRITICAL"])],
        ["HIGH", str(summary["HIGH"])],
        ["MEDIUM", str(summary["MEDIUM"])],
        ["LOW", str(summary["LOW"])],
        ["INFORMATIONAL", str(summary["INFORMATIONAL"])],
        ["TOTAL FINDINGS", str(summary["total"])],
    ]
    t = Table(severity_data, colWidths=[8 * cm, 4 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.lightgrey, colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    elements.append(t)
    return elements


def _build_executive_summary(state: SentinelState, styles) -> list:
    elements = []
    h1 = ParagraphStyle("H1", fontSize=16, textColor=COLOR_ACCENT, fontName="Helvetica-Bold", spaceAfter=10)
    h2 = ParagraphStyle("H2", fontSize=12, textColor=colors.HexColor("#334155"), fontName="Helvetica-Bold", spaceAfter=6)
    body = ParagraphStyle("Body", fontSize=10, spaceAfter=6, leading=14)
    code_box = ParagraphStyle("CodeBox", fontSize=8, fontName="Courier", textColor=colors.HexColor("#0F172A"), leading=10, spaceAfter=10)

    elements.append(Paragraph("Executive Summary & Analyzed Logs", h1))
    if state.executive_summary:
        headline = state.executive_summary.get("executive_headline")
        if headline:
            elements.append(Paragraph(f"<b>Headline:</b> {headline}", body))
            elements.append(Spacer(1, 0.2 * cm))

        summary_text = state.executive_summary.get("executive_narrative", "No summary available.")
        elements.append(Paragraph(summary_text, body))
        elements.append(Spacer(1, 0.4 * cm))

    # Display Submitted User Logs / Code Payload
    if state.raw_input:
        elements.append(Paragraph("Submitted Input / Event Logs Payload:", h2))
        clean_logs = state.raw_input[:2000].replace("\n", "<br/>").replace(" ", "&nbsp;")
        elements.append(Paragraph(clean_logs, code_box))
        elements.append(Spacer(1, 0.4 * cm))

    return elements


def _build_risk_matrix(state: SentinelState, styles) -> list:
    elements = []
    h1 = ParagraphStyle("H1", fontSize=16, textColor=COLOR_ACCENT, fontName="Helvetica-Bold", spaceAfter=10)
    elements.append(Paragraph("Risk Breakdown", h1))

    summary = state.finding_summary
    data = [["Severity", "Count", "Action Required"]]
    for sev, risk in [("CRITICAL", "Immediate Emergency Action Required"), ("HIGH", "High Priority Remediation (24-48 hours)"),
                       ("MEDIUM", "Standard Scheduled Remediation"), ("LOW", "Low Risk Scheduled Review"),
                       ("INFORMATIONAL", "Informational Security Context")]:
        data.append([sev, str(summary.get(sev, 0)), risk])

    t = Table(data, colWidths=[4 * cm, 3 * cm, 9 * cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]
    for i, (sev, _, _) in enumerate([
        ("CRITICAL", "", ""), ("HIGH", "", ""), ("MEDIUM", "", ""),
        ("LOW", "", ""), ("INFORMATIONAL", "", "")
    ], start=1):
        style.append(("BACKGROUND", (0, i), (0, i), _severity_color(sev)))
        style.append(("TEXTCOLOR", (0, i), (0, i), colors.white))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    t.setStyle(TableStyle(style))
    elements.append(t)
    return elements


def _build_findings_table(state: SentinelState, styles) -> list:
    elements = []
    h1 = ParagraphStyle("H1", fontSize=16, textColor=COLOR_ACCENT, fontName="Helvetica-Bold", spaceAfter=10)
    small = ParagraphStyle("Small", fontSize=8, leading=10)

    elements.append(Paragraph("Detected Security Vulnerabilities & Findings", h1))

    data = [["Severity", "Category", "Vulnerability / Finding Title", "File / Source"]]
    for finding in sorted(state.findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"].index(f.severity) if f.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"] else 99):
        data.append([
            finding.severity,
            finding.category[:20],
            Paragraph(finding.title[:80], small),
            finding.file_path or "—",
        ])

    t = Table(data, colWidths=[3 * cm, 4 * cm, 7 * cm, 3 * cm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]
    for i, finding in enumerate(state.findings, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), _severity_color(finding.severity)))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

    t.setStyle(TableStyle(style))
    elements.append(t)
    return elements


def _build_technical_details(state: SentinelState, styles) -> list:
    elements = []
    h1 = ParagraphStyle("H1", fontSize=16, textColor=COLOR_ACCENT, fontName="Helvetica-Bold", spaceAfter=10)
    h2 = ParagraphStyle("H2", fontSize=11, textColor=colors.HexColor("#1E293B"), fontName="Helvetica-Bold", spaceAfter=4)
    body = ParagraphStyle("Body", fontSize=9, spaceAfter=4, leading=12)

    elements.append(Paragraph("Detailed Vulnerabilities & Remediation Advice", h1))

    for finding in state.findings[:30]:
        elements.append(Paragraph(f"[{finding.severity}] {finding.title} ({finding.category})", h2))
        elements.append(Paragraph(f"<b>Description:</b> {finding.description}", body))
        if finding.file_path:
            elements.append(Paragraph(f"<b>Location:</b> {finding.file_path}" + (f" (Line {finding.line_number})" if finding.line_number else ""), body))
        if finding.remediation_advice:
            elements.append(Paragraph(f"<b>Remediation Advice:</b> {finding.remediation_advice}", body))
        if finding.framework_controls:
            elements.append(Paragraph(f"<b>Framework Controls:</b> {', '.join(finding.framework_controls)}", body))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.lightgrey, spaceAfter=8))

    return elements


# ============================================================
# Markdown Report
# ============================================================

def generate_markdown(state: SentinelState) -> str:
    """Generate a Markdown report and return the file path."""
    try:
        output_dir = _ensure_output_dir(state.session_id)
        md_path = output_dir / "report.md"
        summary = state.finding_summary

        lines = [
            "# Sentinel AI — Cybersecurity Intelligence Report",
            "",
            f"**Session ID:** `{state.session_id}`  ",
            f"**Pipeline:** {state.pipeline}  ",
            f"**Generated:** {state.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Status:** {state.status}  ",
            "",
            "---",
            "",
            "## Risk Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| 🔴 CRITICAL | {summary['CRITICAL']} |",
            f"| 🟠 HIGH | {summary['HIGH']} |",
            f"| 🟡 MEDIUM | {summary['MEDIUM']} |",
            f"| 🔵 LOW | {summary['LOW']} |",
            f"| ⚪ INFORMATIONAL | {summary['INFORMATIONAL']} |",
            f"| **Total** | **{summary['total']}** |",
            "",
        ]

        if state.executive_summary:
            lines += [
                "## Executive Summary",
                "",
                state.executive_summary.get("executive_narrative", ""),
                "",
            ]

        lines += ["## Findings", ""]
        for finding in sorted(state.findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"].index(f.severity) if f.severity in ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"] else 99):
            badge = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(finding.severity, "⚪")
            lines += [
                f"### {badge} [{finding.severity}] {finding.title}",
                "",
                f"**Category:** {finding.category}  ",
                f"**File:** `{finding.file_path or 'N/A'}`{f'  **Line:** {finding.line_number}' if finding.line_number else ''}  ",
                "",
                finding.description,
                "",
            ]
            if finding.remediation_advice:
                lines += [f"> **Remediation:** {finding.remediation_advice}", ""]
            if finding.framework_controls:
                lines += [f"**Controls:** {', '.join(finding.framework_controls)}", ""]
            lines.append("---")
            lines.append("")

        md_path.write_text("\n".join(lines), encoding="utf-8")
        log.info("markdown_generated", session_id=state.session_id, path=str(md_path))
        return str(md_path)

    except Exception as e:
        raise ReportGenerationError(f"Markdown generation failed: {e}") from e


# ============================================================
# JSON Report
# ============================================================

def generate_json(state: SentinelState) -> str:
    """Generate a JSON report and return the file path."""
    try:
        output_dir = _ensure_output_dir(state.session_id)
        json_path = output_dir / "report.json"

        # Full state dump — single source of truth
        json_path.write_text(state.model_dump_json(indent=2), encoding="utf-8")
        log.info("json_generated", session_id=state.session_id, path=str(json_path))
        return str(json_path)

    except Exception as e:
        raise ReportGenerationError(f"JSON generation failed: {e}") from e


# ============================================================
# Orchestration helper
# ============================================================

def generate_all_reports(state: SentinelState) -> Dict[str, str]:
    """Generate PDF, Markdown, and JSON reports. Returns paths dict."""
    paths = {}
    errors = []

    for name, fn in [("pdf", generate_pdf), ("markdown", generate_markdown), ("json", generate_json)]:
        try:
            paths[name] = fn(state)
        except Exception as e:
            log.error(f"report_generation_failed", format=name, error=str(e))
            errors.append(f"{name}: {e}")

    if errors:
        log.warning("some_reports_failed", errors=errors)

    return paths
