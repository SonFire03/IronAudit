from __future__ import annotations

from ironaudit.models import Finding, ScoringBreakdown

BASE_SCORE = 100
SEVERITY_CAPS: dict[str, int] = {
    # Strongly penalize critical risk; multiple critical findings can push score near zero.
    "critical": 80,
    # Keep non-critical severities meaningful but bounded for commercial readability.
    "high": 30,
    "medium": 18,
    "low": 8,
    "info": 0,
}


def compute_score_breakdown(findings: list[Finding]) -> ScoringBreakdown:
    deductions_by_severity = dict.fromkeys(SEVERITY_CAPS, 0)

    for finding in findings:
        if finding.status not in {"fail", "warn"}:
            continue
        if finding.points <= 0:
            continue
        if finding.severity not in deductions_by_severity:
            continue
        deductions_by_severity[finding.severity] += finding.points

    capped = {
        severity: min(total, SEVERITY_CAPS[severity])
        for severity, total in deductions_by_severity.items()
    }

    total_deduction = sum(capped.values())
    final_score = max(0, min(100, BASE_SCORE - total_deduction))
    rating = score_rating(final_score)

    return ScoringBreakdown(
        base_score=BASE_SCORE,
        deductions_by_severity=deductions_by_severity,
        caps_by_severity=dict(SEVERITY_CAPS),
        capped_deductions_by_severity=capped,
        total_deduction=total_deduction,
        final_score=final_score,
        rating_label=rating,
    )


def compute_score(findings: list[Finding]) -> int:
    return compute_score_breakdown(findings).final_score


def score_rating(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Weak"
    if score >= 20:
        return "Poor"
    return "Critical"
