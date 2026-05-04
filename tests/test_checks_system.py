from ironaudit.checks import system
from ironaudit.utils import CommandResult


def test_system_run_collects_findings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(system, "hostname", lambda: "audit-host")
    monkeypatch.setattr(system, "detect_distro", lambda: "Ubuntu 24.04")
    monkeypatch.setattr(system.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(system, "run_command", lambda _cmd: CommandResult(0, "up 1 day", ""))

    findings = system.run()
    assert any(item.title == "System information collected" for item in findings)
    assert any(item.title == "Linux kernel branch appears modern" for item in findings)


def test_system_run_flags_legacy_kernel(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(system, "hostname", lambda: "audit-host")
    monkeypatch.setattr(system, "detect_distro", lambda: "Ubuntu 20.04")
    monkeypatch.setattr(system.platform, "release", lambda: "4.15.0")
    monkeypatch.setattr(system, "run_command", lambda _cmd: CommandResult(127, "", "missing"))

    findings = system.run()
    assert any(item.severity == "medium" and item.status == "warn" for item in findings)
