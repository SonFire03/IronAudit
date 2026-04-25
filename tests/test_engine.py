from ironaudit import engine
from ironaudit.models import Finding


def test_resolve_checks_include_exclude() -> None:
    checks = engine.resolve_checks(include=["ssh", "firewall"], exclude=["firewall"])
    assert checks == ["ssh"]


def test_run_scan_handles_check_exception(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def boom() -> list[Finding]:
        raise RuntimeError("boom")

    monkeypatch.setitem(engine.CHECK_REGISTRY, "ssh", boom)
    report = engine.run_scan(include=["ssh"])
    assert len(report.findings) == 1
    assert report.findings[0].status == "unsupported"
    assert "crashed" in report.findings[0].title.lower()


def test_run_scan_server_profile_adjusts_points(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_check() -> list[Finding]:
        return [
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

    monkeypatch.setitem(engine.CHECK_REGISTRY, "services", fake_check)
    report = engine.run_scan(include=["services"], profile="server")
    assert report.findings[0].points >= 12
    assert report.metadata.scan_profile == "server"
