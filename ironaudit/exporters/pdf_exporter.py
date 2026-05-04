from __future__ import annotations

import textwrap
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from ironaudit.models import ScanReport


def write_pdf(report: ScanReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(str(output_path), pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm)
    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]
    body.leading = 14
    small = ParagraphStyle("Small", parent=body, fontSize=9, leading=12, textColor=colors.HexColor("#3F4C5A"))

    duration = (
        f"{report.metadata.duration_seconds:.3f}s"
        if report.metadata.duration_seconds is not None
        else "n/a"
    )

    story = [
        Paragraph("IronAudit Pro - Linux Security Audit Report", h1),
        Paragraph(
            f"Host: <b>{report.metadata.hostname}</b> | Distro: <b>{report.metadata.distro}</b> | "
            f"Date: <b>{report.metadata.scanned_at}</b> | Duration: <b>{duration}</b>",
            body,
        ),
        Paragraph(f"Global Score: <b>{report.score}/100</b> ({report.rating})", h2),
        Spacer(1, 4 * mm),
    ]

    severity_rows = [["Severity", "Count"]]
    for level in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in report.findings if f.severity == level)
        severity_rows.append([level.capitalize(), str(count)])

    severity_table = Table(severity_rows, colWidths=[60 * mm, 24 * mm])
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1F3A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD3DC")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ]
        )
    )
    story.extend([Paragraph("Findings By Severity", h2), severity_table, Spacer(1, 5 * mm)])

    story.append(Paragraph("Technical Details", h2))
    rows = [["Check", "Severity", "Status", "Title", "Recommended Fix"]]
    for finding in report.findings[:40]:
        rows.append(
            [
                finding.check_id,
                finding.severity,
                finding.status,
                _clip(finding.title, 48),
                _clip(finding.remediation, 72),
            ]
        )

    table = Table(rows, colWidths=[22 * mm, 18 * mm, 16 * mm, 58 * mm, 64 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF2F7")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D4DDE8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Command Examples", h2))
    story.append(Paragraph("- sudo apt update && sudo apt upgrade", small))
    story.append(Paragraph("- sudo ufw status verbose", small))
    story.append(Paragraph("- sudo systemctl disable <service>.service", small))
    story.append(Paragraph("- sudo ss -lntup", small))
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("Legal / Safe-Use Disclaimer", h2))
    story.append(
        Paragraph(
            "IronAudit Pro is intended for authorized defensive assessment on systems you own or are "
            "explicitly permitted to audit. It does not perform exploitation or active attack operations.",
            small,
        )
    )

    doc.build(story)


def _clip(text: str, width: int) -> str:
    wrapped = textwrap.wrap(text, width=width)
    if not wrapped:
        return ""
    return "<br/>".join(wrapped[:3])
