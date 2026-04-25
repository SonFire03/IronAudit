from ironaudit.checks import firewall
from ironaudit.utils import CommandResult


def test_firewall_ufw_active(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(firewall, "run_command", lambda _c: CommandResult(0, "Status: active", ""))
    findings = firewall.run()
    assert findings[0].status == "pass"


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
