from __future__ import annotations

from collections import Counter

from ironaudit.models import ScanReport


def to_markdown(report: ScanReport) -> str:
    counts = Counter(f.status for f in report.findings)

    lines: list[str] = []
    lines.append("# IronAudit Report")
    lines.append("")
    lines.append(f"- Hostname: `{report.metadata.hostname}`")
    lines.append(f"- Distribution: `{report.metadata.distro}`")
    lines.append(f"- Scanned at (UTC): `{report.metadata.scanned_at}`")
    if report.metadata.duration_seconds is not None:
        lines.append(f"- Duration: `{report.metadata.duration_seconds:.3f}s`")
    lines.append(f"- Checks: `{', '.join(report.selected_checks)}`")
    lines.append(f"- Score: **{report.score}/100** ({report.rating})")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Pass: {counts.get('pass', 0)}")
    lines.append(f"- Fail: {counts.get('fail', 0)}")
    lines.append(f"- Warn: {counts.get('warn', 0)}")
    lines.append(f"- Info: {counts.get('info', 0)}")
    lines.append(f"- Unsupported: {counts.get('unsupported', 0)}")
    lines.append("")
    lines.append("## Top Remediations")
    lines.append("")
    for remediation in _top_remediations(report, limit=10):
        lines.append(f"- {remediation}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for finding in report.findings:
        lines.append(f"### [{finding.check_id}] {finding.title}")
        lines.append(f"- Severity: `{finding.severity}`")
        lines.append(f"- Status: `{finding.status}`")
        lines.append(f"- Category: `{finding.category}`")
        lines.append(f"- Points: `{finding.points}`")
        lines.append(f"- Evidence: {finding.evidence}")
        lines.append(f"- Remediation: {finding.remediation}")
        if finding.references:
            refs = ", ".join(finding.references)
            lines.append(f"- References: {refs}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _top_remediations(report: ScanReport, limit: int) -> list[str]:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    status_rank = {"fail": 0, "warn": 1, "pass": 2, "info": 3, "unsupported": 4}
    risky = [f for f in report.findings if f.status in {"fail", "warn"}]
    risky = sorted(
        risky,
        key=lambda finding: (
            status_rank.get(finding.status, 99),
            severity_rank.get(finding.severity, 99),
            -finding.points,
            finding.check_id,
        ),
    )

    seen: set[str] = set()
    output: list[str] = []
    for finding in risky:
        text = finding.remediation.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
        if len(output) >= limit:
            break
    if output:
        return output
    return ["No immediate remediation required based on current findings."]
