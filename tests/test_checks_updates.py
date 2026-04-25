from ironaudit.checks import updates
from ironaudit.utils import CommandResult


def test_updates_unsupported_distro(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(updates, "distro_id_like", lambda: {"arch"})
    findings = updates.run()
    assert findings[0].status == "unsupported"


def test_updates_pending(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(updates, "distro_id_like", lambda: {"ubuntu"})
    monkeypatch.setattr(
        updates,
        "run_command",
        lambda _c: CommandResult(0, "Listing...\npkg1/jammy\npkg2/jammy", ""),
    )
    findings = updates.run()
    assert findings[0].status == "warn"
    assert findings[0].points == 5
