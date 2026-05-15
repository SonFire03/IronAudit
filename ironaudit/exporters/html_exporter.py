from __future__ import annotations

import html
from collections import Counter

from ironaudit.models import Finding, ScanReport

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def to_html(report: ScanReport) -> str:
    duration = (
        f"{report.metadata.duration_seconds:.3f}s"
        if report.metadata.duration_seconds is not None
        else "n/a"
    )
    status_counts = Counter(f.status for f in report.findings)
    severity_counts = Counter(f.severity for f in report.findings)

    grouped: dict[str, list[Finding]] = {level: [] for level in SEVERITY_ORDER}
    for finding in report.findings:
        grouped.setdefault(finding.severity, []).append(finding)

    severity_blocks = "".join(_severity_section(level, grouped.get(level, [])) for level in SEVERITY_ORDER)
    scoring_block = _scoring_breakdown(report)

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>IronAudit Pro Report</title>
  <style>
    :root {{
      --ink: #16202a;
      --slate: #526170;
      --paper: #f4f7fb;
      --card: #ffffff;
      --accent: #0c4a7d;
      --accent-soft: #dce8f5;
      --critical: #b00020;
      --high: #d1431f;
      --medium: #b7791f;
      --low: #2f855a;
      --info: #2b6cb0;
      --border: #d7e0ea;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "Source Sans 3", "Segoe UI", Tahoma, sans-serif; color: var(--ink); background: linear-gradient(140deg, #f7f9fc 0%, #edf3f9 55%, #e7eef7 100%); }}
    .wrap {{ max-width: 1200px; margin: 24px auto; padding: 0 16px; }}
    .hero {{ background: linear-gradient(150deg, #0d3f66 0%, #155384 65%, #1f6aa6 100%); color: #fff; border-radius: 16px; padding: 24px; box-shadow: 0 12px 30px rgba(12, 44, 73, .18); }}
    .hero h1 {{ margin: 0 0 6px; font-size: 1.8rem; }}
    .hero p {{ margin: 4px 0; color: #e7f2fc; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(150px, 1fr)); gap: 12px; margin-top: 14px; }}
    .metric {{ background: rgba(255,255,255,.11); border: 1px solid rgba(255,255,255,.22); border-radius: 12px; padding: 10px 12px; }}
    .metric .k {{ font-size: .8rem; opacity: .86; text-transform: uppercase; }}
    .metric .v {{ font-size: 1.36rem; font-weight: 700; }}
    .section {{ background: var(--card); border: 1px solid var(--border); border-radius: 14px; margin-top: 14px; padding: 16px; box-shadow: 0 4px 14px rgba(17, 40, 63, .05); }}
    h2 {{ margin: 0 0 12px; font-size: 1.2rem; color: #103a5f; }}
    .summary {{ display: grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 10px; }}
    .pill {{ border-radius: 999px; padding: 2px 10px; font-size: .8rem; font-weight: 700; display: inline-block; }}
    .critical {{ background: #ffe4ea; color: var(--critical); }}
    .high {{ background: #ffe8e0; color: var(--high); }}
    .medium {{ background: #fff2df; color: var(--medium); }}
    .low {{ background: #e3f5ea; color: var(--low); }}
    .info {{ background: #e3eefc; color: var(--info); }}
    .finding {{ border: 1px solid var(--border); border-radius: 12px; padding: 12px; margin-top: 10px; background: #fff; }}
    .muted {{ color: var(--slate); }}
    code {{ background: #f2f6fb; border: 1px solid #e3eaf3; border-radius: 6px; padding: 1px 6px; }}
    ul {{ margin: 0; padding-left: 18px; }}
    .disclaimer {{ font-size: .9rem; color: #445564; }}
    @media (max-width: 900px) {{ .grid {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }} .summary {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }} }}
  </style>
</head>
<body>
  <div class='wrap'>
    <section class='hero'>
      <h1>IronAudit Pro - Security Audit Report</h1>
      <p>Executive Summary for authorized local Linux security posture assessment.</p>
      <p>Host: <strong>{html.escape(report.metadata.hostname)}</strong> | Distribution: <strong>{html.escape(report.metadata.distro)}</strong></p>
      <p>Scan date: <strong>{html.escape(report.metadata.scanned_at)}</strong> | Duration: <strong>{duration}</strong> | Profile: <strong>{html.escape(report.metadata.scan_profile or 'workstation')}</strong></p>
      <div class='grid'>
        <div class='metric'><div class='k'>Global Score</div><div class='v'>{report.score}/100</div></div>
        <div class='metric'><div class='k'>Risk Rating</div><div class='v'>{html.escape(report.rating)}</div></div>
        <div class='metric'><div class='k'>Findings</div><div class='v'>{len(report.findings)}</div></div>
        <div class='metric'><div class='k'>Failures</div><div class='v'>{status_counts.get('fail', 0)}</div></div>
      </div>
    </section>

    <section class='section'>
      <h2>Findings By Severity</h2>
      <div class='summary'>
        <div><span class='pill critical'>Critical</span><div>{severity_counts.get('critical', 0)}</div></div>
        <div><span class='pill high'>High</span><div>{severity_counts.get('high', 0)}</div></div>
        <div><span class='pill medium'>Medium</span><div>{severity_counts.get('medium', 0)}</div></div>
        <div><span class='pill low'>Low</span><div>{severity_counts.get('low', 0)}</div></div>
        <div><span class='pill info'>Info</span><div>{severity_counts.get('info', 0)}</div></div>
      </div>
    </section>

    <section class='section'>
      <h2>Scoring Breakdown</h2>
      {scoring_block}
    </section>

    <section class='section'>
      <h2>Technical Details</h2>
      {severity_blocks}
    </section>

    <section class='section'>
      <h2>Recommended Fixes</h2>
      <ul>
        {_top_fixes(report)}
      </ul>
    </section>

    <section class='section'>
      <h2>Command Examples</h2>
      <ul>
        <li><code>sudo apt update && sudo apt upgrade</code></li>
        <li><code>sudo ufw status verbose</code></li>
        <li><code>sudo ss -lntup</code></li>
        <li><code>sudo systemctl list-unit-files --type=service --state=enabled</code></li>
        <li><code>sudo chmod o-w &lt;path&gt;</code></li>
      </ul>
    </section>

    <section class='section'>
      <h2>Legal / Safe-Use Disclaimer</h2>
      <p class='disclaimer'>IronAudit Pro is designed for defensive security auditing on systems you own or are explicitly authorized to assess. The tool performs local read-only checks and does not include exploit code or aggressive scanning behavior.</p>
    </section>
  </div>
</body>
</html>
"""


def _severity_section(level: str, findings: list[Finding]) -> str:
    if not findings:
        return f"<h3>{level.capitalize()}</h3><p class='muted'>No findings.</p>"

    blocks = [f"<h3>{level.capitalize()} ({len(findings)})</h3>"]
    for finding in findings:
        blocks.append(
            "<article class='finding'>"
            f"<div><strong>{html.escape(finding.title)}</strong> <span class='pill {html.escape(finding.severity)}'>{html.escape(finding.severity)}</span></div>"
            f"<div class='muted'>Check: {html.escape(finding.check_id)} | Status: {html.escape(finding.status)} | Category: {html.escape(finding.category)} | Points: {finding.points}</div>"
            f"<p><strong>Evidence:</strong> {html.escape(finding.evidence)}</p>"
            f"<p><strong>Recommended fix:</strong> {html.escape(finding.remediation)}</p>"
            "</article>"
        )
    return "".join(blocks)


def _top_fixes(report: ScanReport) -> str:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    status_rank = {"fail": 0, "warn": 1, "pass": 2, "info": 3, "unsupported": 4}
    risky = [f for f in report.findings if f.status in {"fail", "warn"}]
    risky = sorted(
        risky,
        key=lambda finding: (
            status_rank.get(finding.status, 99),
            severity_rank.get(finding.severity, 99),
            -finding.points,
            finding.check_id,
        ),
    )
    if not risky:
        return "<li>No immediate remediation required based on current findings.</li>"

    seen: set[str] = set()
    items: list[str] = []
    for finding in risky:
        if finding.remediation in seen:
            continue
        seen.add(finding.remediation)
        items.append(f"<li>{html.escape(finding.remediation)}</li>")
        if len(items) >= 10:
            break
    return "".join(items)


def _scoring_breakdown(report: ScanReport) -> str:
    if report.scoring is None:
        return "<p class='muted'>Scoring breakdown not available in this report.</p>"
    rows: list[str] = []
    for level in SEVERITY_ORDER:
        raw = report.scoring.deductions_by_severity.get(level, 0)
        cap = report.scoring.caps_by_severity.get(level, 0)
        used = report.scoring.capped_deductions_by_severity.get(level, 0)
        rows.append(
            f"<tr><td>{html.escape(level)}</td><td>{raw}</td><td>{cap}</td><td>{used}</td></tr>"
        )
    return (
        "<p>"
        f"Base score: <strong>{report.scoring.base_score}</strong> | "
        f"Total deduction: <strong>{report.scoring.total_deduction}</strong> | "
        f"Final score: <strong>{report.scoring.final_score}</strong> | "
        f"Rating label: <strong>{html.escape(report.scoring.rating_label)}</strong>"
        "</p>"
        "<table style='width:100%; border-collapse:collapse;'>"
        "<thead><tr><th style='text-align:left'>Severity</th><th style='text-align:left'>Raw deduction</th>"
        "<th style='text-align:left'>Cap</th><th style='text-align:left'>Capped deduction</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )
