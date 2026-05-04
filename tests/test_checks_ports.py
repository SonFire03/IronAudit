from ironaudit.checks import ports
from ironaudit.utils import CommandResult


def test_ports_run_handles_command_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(ports, "run_command", lambda _cmd: CommandResult(127, "", "missing"))
    findings = ports.run()
    assert len(findings) == 1
    assert findings[0].title.startswith("Unable to enumerate")


def test_ports_run_warns_for_multiple_exposed(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    output = """State Recv-Q Send-Q Local Address:Port Peer Address:Port
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 0.0.0.0:80 0.0.0.0:*
LISTEN 0 128 0.0.0.0:443 0.0.0.0:*
LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*
LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*
"""
    monkeypatch.setattr(ports, "run_command", lambda _cmd: CommandResult(0, output, ""))
    findings = ports.run()
    assert any(item.status == "warn" for item in findings)
