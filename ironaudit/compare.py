from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ironaudit.models import Finding, ScanReport
from ironaudit.reporting import severity_counter, top_remediations


@dataclass(slots=True)
class ComparisonResult:
    before_score: int
    after_score: int
    score_delta: int
    new_risks: list[Finding]
    resolved_risks: list[Finding]
    new_risks_by_severity: dict[str, int]
    resolved_risks_by_severity: dict[str, int]
    top_new_remediations: list[str]


def load_report(path: Path) -> ScanReport:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid report format in {path}")
    return ScanReport.from_dict(data)


def compare_reports(before: ScanReport, after: ScanReport) -> ComparisonResult:
    before_risks = _risk_map(before.findings)
    after_risks = _risk_map(after.findings)

    new_keys = set(after_risks.keys()) - set(before_risks.keys())
    resolved_keys = set(before_risks.keys()) - set(after_risks.keys())

    new_risks = [after_risks[key] for key in sorted(new_keys)]
    resolved_risks = [before_risks[key] for key in sorted(resolved_keys)]
    new_risk_counts = dict(severity_counter(new_risks))
    resolved_risk_counts = dict(severity_counter(resolved_risks))

    return ComparisonResult(
        before_score=before.score,
        after_score=after.score,
        score_delta=after.score - before.score,
        new_risks=new_risks,
        resolved_risks=resolved_risks,
        new_risks_by_severity=new_risk_counts,
        resolved_risks_by_severity=resolved_risk_counts,
        top_new_remediations=top_remediations(new_risks, limit=5),
    )


def _risk_map(findings: list[Finding]) -> dict[str, Finding]:
    result: dict[str, Finding] = {}
    for finding in findings:
        if finding.status not in {"fail", "warn"}:
            continue
        key = f"{finding.check_id}|{finding.title}|{finding.severity}|{finding.category}"
        result[key] = finding
    return result
