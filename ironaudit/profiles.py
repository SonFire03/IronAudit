from __future__ import annotations

from dataclasses import dataclass, field

from ironaudit.models import Finding


@dataclass(frozen=True, slots=True)
class ProfileSpec:
    name: str
    description: str
    include_checks: list[str] = field(default_factory=list)
    exclude_checks: list[str] = field(default_factory=list)
    point_multiplier: float = 1.0
    category_multipliers: dict[str, float] = field(default_factory=dict)


PROFILE_REGISTRY: dict[str, ProfileSpec] = {
    "workstation": ProfileSpec(
        name="workstation",
        description="Balanced profile for daily-user Linux workstations.",
        include_checks=[],
        exclude_checks=[],
        point_multiplier=1.0,
        category_multipliers={
            "network": 0.9,
            "filesystem": 1.0,
            "identity": 1.0,
            "authentication": 1.0,
        },
    ),
    "server": ProfileSpec(
        name="server",
        description="Stricter profile for internet-facing or production servers.",
        include_checks=[],
        exclude_checks=[],
        point_multiplier=1.0,
        category_multipliers={
            "network": 1.25,
            "firewall": 1.25,
            "authentication": 1.2,
            "identity": 1.15,
            "patching": 1.1,
        },
    ),
    "minimal": ProfileSpec(
        name="minimal",
        description="Minimal baseline profile with critical hardening checks only.",
        include_checks=["ssh", "firewall", "users", "auth"],
        exclude_checks=[],
        point_multiplier=0.95,
        category_multipliers={
            "network": 1.0,
            "authentication": 1.0,
            "identity": 1.0,
            "firewall": 1.1,
        },
    ),
}


def available_profiles() -> list[str]:
    return sorted(PROFILE_REGISTRY.keys())


def get_profile(name: str | None) -> ProfileSpec:
    key = (name or "workstation").strip().lower()
    profile = PROFILE_REGISTRY.get(key)
    if profile is None:
        raise ValueError(f"Unknown profile: {name}. Available: {', '.join(available_profiles())}")
    return profile


def apply_profile(findings: list[Finding], profile_name: str | None) -> list[Finding]:
    spec = get_profile(profile_name)

    for finding in findings:
        if finding.status not in {"fail", "warn"} or finding.points <= 0:
            continue

        category_mult = spec.category_multipliers.get(finding.category, 1.0)
        multiplier = spec.point_multiplier * category_mult
        adjusted = int(round(finding.points * multiplier))
        finding.points = max(1, adjusted)

    return findings
