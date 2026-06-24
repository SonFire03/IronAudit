from ironaudit.checks import firewall
from ironaudit.utils import CommandResult


def test_firewall_ufw_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def fake_run(cmd: list[str]) -> CommandResult:
        if cmd == ["ufw", "status", "verbose"]:
            return CommandResult(0, "Default: deny (incoming), allow (outgoing), deny (routed)", "")
        return CommandResult(0, "Status: active", "")

    monkeypatch.setattr(firewall, "run_command", fake_run)
    findings = firewall.run()
    assert findings[0].status == "pass"
    assert any(item.title == "UFW default inbound policy is restrictive" for item in findings)


def test_firewall_none_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    responses = {
        "ufw": CommandResult(127, "", "not found"),
        "nft": CommandResult(127, "", "not found"),
        "iptables": CommandResult(127, "", "not found"),
    }

    def fake_run(cmd: list[str]) -> CommandResult:
        return responses[cmd[0]]

    monkeypatch.setattr(firewall, "run_command", fake_run)
    findings = firewall.run()
    assert findings[0].status == "fail"
