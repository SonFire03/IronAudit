import pytest

from ironaudit.models import Finding
from ironaudit.profiles import apply_profile, available_profiles, get_profile


def test_available_profiles() -> None:
    profiles = available_profiles()
    assert "workstation" in profiles
    assert "server" in profiles
    assert "minimal" in profiles


def test_get_profile_unknown() -> None:
    with pytest.raises(ValueError):
        get_profile("unknown")


def test_apply_profile_server_increases_network_points() -> None:
    findings = [
        Finding(
            check_id="services",
            title="Sensitive network ports exposed",
            severity="high",
            status="warn",
            category="network",
            evidence="x",
            remediation="y",
            points=10,
        )
    ]
    apply_profile(findings, "server")
    assert findings[0].points >= 12


def test_apply_profile_minimal_includes_only_core_checks() -> None:
    profile = get_profile("minimal")
    assert set(profile.include_checks) == {"ssh", "firewall", "users", "auth"}
