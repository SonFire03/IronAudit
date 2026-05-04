from ironaudit.checks import enabled_services
from ironaudit.utils import CommandResult


def test_enabled_services_handles_unavailable_systemctl(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(enabled_services, "run_command", lambda _cmd: CommandResult(127, "", "missing"))
    findings = enabled_services.run()
    assert len(findings) == 1
    assert findings[0].status == "info"


def test_enabled_services_flags_legacy_services(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    output = """sshd.service enabled
telnet.service enabled
cron.service enabled
"""
    monkeypatch.setattr(enabled_services, "run_command", lambda _cmd: CommandResult(0, output, ""))
    findings = enabled_services.run()
    assert any(item.status == "fail" for item in findings)
