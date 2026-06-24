from __future__ import annotations

from collections import Counter

from ironaudit.models import Finding, ScanReport

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
STATUS_ORDER = ["fail", "warn", "pass", "info", "unsupported"]


def risk_sort_key(finding: Finding) -> tuple[int, int, int, str, str]:
    severity_rank = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}
    status_rank = {name: idx for idx, name in enumerate(STATUS_ORDER)}
    return (
        status_rank.get(finding.status, len(STATUS_ORDER)),
        severity_rank.get(finding.severity, len(SEVERITY_ORDER)),
        -finding.points,
        finding.check_id,
        finding.title,
    )


def top_remediations(findings: list[Finding], limit: int = 5) -> list[str]:
    risky = sorted((finding for finding in findings if finding.status in {"fail", "warn"}), key=risk_sort_key)

    seen: set[str] = set()
    remediations: list[str] = []
    for finding in risky:
        remediation = finding.remediation.strip()
        if not remediation or remediation in seen:
            continue
        seen.add(remediation)
        remediations.append(remediation)
        if len(remediations) >= limit:
            break
    return remediations


def severity_counter(findings: list[Finding]) -> Counter[str]:
    counter = Counter[str]()
    for finding in findings:
        counter[finding.severity] += 1
    return counter


def status_counter(findings: list[Finding]) -> Counter[str]:
    counter = Counter[str]()
    for finding in findings:
        counter[finding.status] += 1
    return counter


def report_risks(report: ScanReport) -> list[Finding]:
    return sorted((finding for finding in report.findings if finding.status in {"fail", "warn"}), key=risk_sort_key)
