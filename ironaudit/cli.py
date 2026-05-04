from __future__ import annotations

import json
import webbrowser
from contextlib import suppress
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from ironaudit import __version__
from ironaudit.compare import compare_reports, load_report
from ironaudit.engine import available_checks, run_scan
from ironaudit.exporters.html_exporter import to_html
from ironaudit.exporters.json_exporter import to_json
from ironaudit.exporters.markdown_exporter import to_markdown
from ironaudit.exporters.pdf_exporter import write_pdf
from ironaudit.exporters.sarif_exporter import to_sarif
from ironaudit.history import (
    latest_two_reports,
    list_snapshots,
    load_snapshot_by_id,
    save_snapshot,
)
from ironaudit.models import ScanReport
from ironaudit.profiles import available_profiles
from ironaudit.webapp import WebConfig, serve_web

app = typer.Typer(help="IronAudit - Linux security posture auditor")
history_app = typer.Typer(help="Manage audit history snapshots")
app.add_typer(history_app, name="history")
console = Console()


def _split_csv(values: str | None) -> list[str] | None:
    if not values:
        return None
    return [item.strip() for item in values.split(",") if item.strip()]


def _render_terminal(
    report_json: bool,
    report_md: bool,
    report_html: bool,
    report_pdf: bool,
    report_sarif: bool,
    output: Path | None,
    report: ScanReport,
) -> None:
    if report_json:
        payload = to_json(report)
    elif report_md:
        payload = to_markdown(report)
    elif report_html:
        payload = to_html(report)
    elif report_pdf:
        payload = ""
    elif report_sarif:
        payload = to_sarif(report)
    else:
        payload = ""

    if report_pdf:
        if output is None:
            raise typer.BadParameter("--output is required with --pdf.")
        write_pdf(report, output)
        console.print(f"Report written to {output}")
        return

    if report_json or report_md or report_html or report_sarif:
        if output:
            output.write_text(payload, encoding="utf-8")
            console.print(f"Report written to {output}")
        else:
            console.print(payload)
        return

    table = Table(title="IronAudit Findings", box=box.SIMPLE_HEAVY)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Points", justify="right")

    for finding in report.findings:
        table.add_row(
            finding.check_id,
            finding.status,
            finding.severity,
            finding.title,
            str(finding.points),
        )

    console.print(table)
    console.print(f"Score: {report.score}/100 ({report.rating})")
    if report.scoring is not None:
        sev_order = ["critical", "high", "medium", "low", "info"]
        summary = []
        for sev in sev_order:
            raw = report.scoring.deductions_by_severity.get(sev, 0)
            cap = report.scoring.caps_by_severity.get(sev, 0)
            used = report.scoring.capped_deductions_by_severity.get(sev, 0)
            summary.append(f"{sev} {used}/{cap} (raw {raw})")
        console.print(
            "Scoring breakdown: "
            f"base {report.scoring.base_score} | "
            f"deduction {report.scoring.total_deduction} | "
            f"final {report.scoring.final_score} | "
            + "; ".join(summary)
        )

    if output:
        output.write_text(to_json(report), encoding="utf-8")
        console.print(f"JSON report written to {output}")


@app.command()
def scan(
    json_output: Annotated[bool, typer.Option("--json", help="Print/export report as JSON")] = False,
    md_output: Annotated[bool, typer.Option("--md", help="Print/export report as Markdown")] = False,
    html_output: Annotated[bool, typer.Option("--html", help="Print/export report as HTML")] = False,
    pdf_output: Annotated[bool, typer.Option("--pdf", help="Export report as PDF")] = False,
    sarif_output: Annotated[bool, typer.Option("--sarif", help="Print/export report as SARIF")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Output file path")] = None,
    save_history: Annotated[
        bool, typer.Option("--save-history/--no-save-history", help="Store snapshot in local history")
    ] = False,
    label: Annotated[str | None, typer.Option("--label", help="Optional snapshot label")] = None,
    profile: Annotated[
        str, typer.Option("--profile", help="Scan profile: workstation, server, minimal")
    ] = "workstation",
    checks: Annotated[str | None, typer.Option("--checks", help="Comma-separated checks to include")] = None,
    exclude: Annotated[str | None, typer.Option("--exclude", help="Comma-separated checks to exclude")] = None,
) -> None:
    """Run local Linux hardening audit checks."""
    output_modes = [json_output, md_output, html_output, pdf_output, sarif_output]
    if sum(1 for mode in output_modes if mode) > 1:
        raise typer.BadParameter("Use only one output mode among --json, --md, --html, --pdf, --sarif.")

    if profile not in available_profiles():
        raise typer.BadParameter(
            f"Unknown profile '{profile}'. Available profiles: {', '.join(available_profiles())}"
        )

    include_checks = _split_csv(checks)
    exclude_checks = _split_csv(exclude)

    report = run_scan(include=include_checks, exclude=exclude_checks, profile=profile)

    if save_history:
        path = save_snapshot(report, label=label)
        console.print(f"Snapshot saved: {path}")

    _render_terminal(
        report_json=json_output,
        report_md=md_output,
        report_html=html_output,
        report_pdf=pdf_output,
        report_sarif=sarif_output,
        output=output,
        report=report,
    )


@app.command()
def info() -> None:
    """Display project and check metadata."""
    table = Table(title="IronAudit Info", box=box.SIMPLE)
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Version", __version__)
    table.add_row("Tagline", "Linux security posture auditor with scoring, findings, and remediation guidance.")
    table.add_row("Checks", ", ".join(available_checks()))
    table.add_row("Profiles", ", ".join(available_profiles()))
    console.print(table)


@app.command()
def version() -> None:
    """Display CLI version."""
    console.print(__version__)


@app.command()
def web(
    host: Annotated[str, typer.Option("--host", help="Bind host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port")] = 8765,
    open_browser: Annotated[
        bool, typer.Option("--open-browser/--no-open-browser", help="Open browser automatically")
    ] = True,
) -> None:
    """Run local web interface for IronAudit."""
    url = f"http://{host}:{port}/"
    console.print(f"Starting IronAudit Web on {url}")
    console.print("Press Ctrl+C to stop.")
    if open_browser:
        with suppress(Exception):
            webbrowser.open(url)
    serve_web(WebConfig(host=host, port=port))


@app.command()
def compare(
    baseline: Annotated[Path, typer.Argument(help="Path to baseline JSON report")],
    current: Annotated[Path, typer.Argument(help="Path to current JSON report")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit comparison as JSON")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Write comparison output to file")] = None,
) -> None:
    """Compare two IronAudit JSON reports."""
    before = load_report(baseline)
    after = load_report(current)
    result = compare_reports(before, after)

    payload = {
        "before_score": result.before_score,
        "after_score": result.after_score,
        "score_delta": result.score_delta,
        "new_risks_count": len(result.new_risks),
        "resolved_risks_count": len(result.resolved_risks),
        "new_risks": [item.to_dict() for item in result.new_risks],
        "resolved_risks": [item.to_dict() for item in result.resolved_risks],
    }

    if json_output:
        data = json.dumps(payload, indent=2)
        if output:
            output.write_text(data, encoding="utf-8")
            console.print(f"Comparison written to {output}")
        else:
            console.print(data)
        return

    table = Table(title="IronAudit Comparison", box=box.SIMPLE_HEAVY)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Baseline score", str(result.before_score))
    table.add_row("Current score", str(result.after_score))
    table.add_row("Score delta", f"{result.score_delta:+d}")
    table.add_row("New risks", str(len(result.new_risks)))
    table.add_row("Resolved risks", str(len(result.resolved_risks)))
    console.print(table)

    if result.new_risks:
        console.print("[bold red]New risks:[/bold red]")
        for finding in result.new_risks[:10]:
            console.print(f"- [{finding.check_id}] {finding.title} ({finding.severity}/{finding.status})")

    if result.resolved_risks:
        console.print("[bold green]Resolved risks:[/bold green]")
        for finding in result.resolved_risks[:10]:
            console.print(f"- [{finding.check_id}] {finding.title} ({finding.severity}/{finding.status})")


@history_app.command("save")
def history_save(
    profile: Annotated[
        str, typer.Option("--profile", help="Scan profile: workstation, server, minimal")
    ] = "workstation",
    checks: Annotated[str | None, typer.Option("--checks", help="Comma-separated checks to include")] = None,
    exclude: Annotated[str | None, typer.Option("--exclude", help="Comma-separated checks to exclude")] = None,
    label: Annotated[str | None, typer.Option("--label", help="Optional snapshot label")] = None,
) -> None:
    """Run scan and save a new history snapshot."""
    if profile not in available_profiles():
        raise typer.BadParameter(
            f"Unknown profile '{profile}'. Available profiles: {', '.join(available_profiles())}"
        )
    report = run_scan(include=_split_csv(checks), exclude=_split_csv(exclude), profile=profile)
    path = save_snapshot(report, label=label)
    console.print(f"Snapshot saved: {path}")
    console.print(f"Score: {report.score}/100 ({report.rating})")


@history_app.command("list")
def history_list(
    limit: Annotated[int, typer.Option("--limit", min=1, max=200, help="Max snapshots to list")] = 20,
) -> None:
    """List stored history snapshots."""
    snapshots = list_snapshots(limit=limit)
    table = Table(title="IronAudit History", box=box.SIMPLE_HEAVY)
    table.add_column("Snapshot ID")
    table.add_column("Host")
    table.add_column("Scanned At")
    table.add_column("Score")
    table.add_column("Rating")

    for snap in snapshots:
        table.add_row(snap.snapshot_id, snap.hostname, snap.created_at, str(snap.score), snap.rating)
    console.print(table)
    if not snapshots:
        console.print("No snapshots found. Run `ironaudit history save` first.")


@history_app.command("show")
def history_show(
    snapshot_id: Annotated[str, typer.Argument(help="Snapshot ID from `ironaudit history list`")],
    json_output: Annotated[bool, typer.Option("--json", help="Print snapshot as JSON")] = False,
    md_output: Annotated[bool, typer.Option("--md", help="Print snapshot as Markdown")] = False,
    html_output: Annotated[bool, typer.Option("--html", help="Print snapshot as HTML")] = False,
    pdf_output: Annotated[bool, typer.Option("--pdf", help="Print snapshot as PDF")] = False,
    sarif_output: Annotated[bool, typer.Option("--sarif", help="Print snapshot as SARIF")] = False,
    output: Annotated[Path | None, typer.Option("--output", help="Output file path for exported snapshot")] = None,
) -> None:
    """Show a stored history snapshot."""
    output_modes = [json_output, md_output, html_output, pdf_output, sarif_output]
    if sum(1 for mode in output_modes if mode) > 1:
        raise typer.BadParameter("Use only one output mode among --json, --md, --html, --pdf, --sarif.")

    report = load_snapshot_by_id(snapshot_id)
    _render_terminal(
        report_json=json_output,
        report_md=md_output,
        report_html=html_output,
        report_pdf=pdf_output,
        report_sarif=sarif_output,
        output=output,
        report=report,
    )


@history_app.command("trend")
def history_trend(
    limit: Annotated[int, typer.Option("--limit", min=2, max=200, help="Number of recent snapshots")] = 20,
) -> None:
    """Display score trend over recent snapshots."""
    snapshots = list_snapshots(limit=limit)
    if len(snapshots) < 2:
        console.print("Need at least two snapshots. Run `ironaudit history save` multiple times.")
        return

    ordered = list(reversed(snapshots))
    table = Table(title="IronAudit Trend", box=box.SIMPLE_HEAVY)
    table.add_column("#", justify="right")
    table.add_column("Snapshot ID")
    table.add_column("Score", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Rating")

    prev_score: int | None = None
    for idx, snap in enumerate(ordered, start=1):
        delta = "-"
        if prev_score is not None:
            diff = snap.score - prev_score
            delta = f"{diff:+d}"
        table.add_row(str(idx), snap.snapshot_id, str(snap.score), delta, snap.rating)
        prev_score = snap.score
    console.print(table)


@history_app.command("compare-latest")
def history_compare_latest(
    json_output: Annotated[bool, typer.Option("--json", help="Emit comparison as JSON")] = False,
) -> None:
    """Compare the two latest snapshots."""
    pair = latest_two_reports()
    if pair is None:
        console.print("Need at least two valid snapshots to compare.")
        return

    before, after = pair
    result = compare_reports(before, after)
    payload = {
        "before_score": result.before_score,
        "after_score": result.after_score,
        "score_delta": result.score_delta,
        "new_risks_count": len(result.new_risks),
        "resolved_risks_count": len(result.resolved_risks),
        "new_risks": [item.to_dict() for item in result.new_risks],
        "resolved_risks": [item.to_dict() for item in result.resolved_risks],
    }

    if json_output:
        console.print(json.dumps(payload, indent=2))
        return

    table = Table(title="Latest Snapshot Comparison", box=box.SIMPLE_HEAVY)
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Baseline score", str(result.before_score))
    table.add_row("Current score", str(result.after_score))
    table.add_row("Score delta", f"{result.score_delta:+d}")
    table.add_row("New risks", str(len(result.new_risks)))
    table.add_row("Resolved risks", str(len(result.resolved_risks)))
    console.print(table)

if __name__ == "__main__":
    app()
