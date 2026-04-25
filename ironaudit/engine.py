from __future__ import annotations

from collections.abc import Callable
from time import perf_counter

from ironaudit.checks import auth, firewall, permissions, services, ssh, updates, users
from ironaudit.models import Finding, ScanMetadata, ScanReport
from ironaudit.scoring import compute_score, score_rating
from ironaudit.utils import detect_distro, hostname

CheckFn = Callable[[], list[Finding]]

CHECK_REGISTRY: dict[str, CheckFn] = {
    "ssh": ssh.run,
    "firewall": firewall.run,
    "services": services.run,
    "users": users.run,
    "permissions": permissions.run,
    "updates": updates.run,
    "auth": auth.run,
}


def available_checks() -> list[str]:
    return sorted(CHECK_REGISTRY.keys())


def resolve_checks(include: list[str] | None = None, exclude: list[str] | None = None) -> list[str]:
    selected = available_checks()

    if include:
        include_set = {item.strip() for item in include if item.strip()}
        selected = [name for name in selected if name in include_set]

    if exclude:
        exclude_set = {item.strip() for item in exclude if item.strip()}
        selected = [name for name in selected if name not in exclude_set]

    return selected


def run_scan(include: list[str] | None = None, exclude: list[str] | None = None) -> ScanReport:
    started = perf_counter()
    selected = resolve_checks(include=include, exclude=exclude)
    findings: list[Finding] = []

    for check_name in selected:
        check = CHECK_REGISTRY.get(check_name)
        if check is None:
            continue
        try:
            findings.extend(check())
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    check_id=check_name,
                    title=f"Check crashed: {check_name}",
                    severity="medium",
                    status="unsupported",
                    category="runtime",
                    evidence=str(exc),
                    remediation="Inspect check implementation and runtime prerequisites.",
                    points=0,
                )
            )

    score = compute_score(findings)
    rating = score_rating(score)

    duration = round(perf_counter() - started, 3)
    metadata = ScanMetadata(hostname=hostname(), distro=detect_distro(), duration_seconds=duration)
    return ScanReport(
        metadata=metadata,
        selected_checks=selected,
        findings=findings,
        score=score,
        rating=rating,
    )
