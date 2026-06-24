from pathlib import Path

from ironaudit.checks import ssh
from ironaudit.utils import CommandResult


def test_ssh_reports_root_login_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(
        ssh,
        "safe_read_text",
        lambda _p: "PermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication no\nPermitEmptyPasswords yes\nX11Forwarding yes\nMaxAuthTries 6\nPort 22\n",
    )
    monkeypatch.setattr(ssh, "run_command", lambda _c: CommandResult(0, "LISTEN 0 128 0.0.0.0:22", ""))

    findings = ssh.run()

    assert any(f.title == "SSH root login is enabled" and f.status == "fail" for f in findings)
    assert any(f.title == "SSH password authentication enabled" and f.status == "fail" for f in findings)
    assert any(f.title == "SSH empty passwords are allowed" and f.status == "fail" for f in findings)
    assert any(f.title == "SSH X11 forwarding is enabled" and f.status == "warn" for f in findings)
    assert any(f.title == "SSH authentication retry budget is high" and f.status == "warn" for f in findings)
    assert any(
        f.title == "SSH public key authentication not explicitly enabled" and f.status == "warn"
        for f in findings
    )


def test_ssh_missing_config(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(Path, "exists", lambda self: False)
    findings = ssh.run()
    assert findings[0].status == "warn"
