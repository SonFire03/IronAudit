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
