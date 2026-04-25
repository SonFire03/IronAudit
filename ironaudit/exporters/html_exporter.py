from __future__ import annotations

import html
from collections import Counter

from ironaudit.models import ScanReport


def to_html(report: ScanReport) -> str:
    counts = Counter(f.status for f in report.findings)

    rows: list[str] = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(finding.check_id)}</td>"
            f"<td><span class='chip status-{html.escape(finding.status)}'>{html.escape(finding.status)}</span></td>"
            f"<td><span class='chip sev-{html.escape(finding.severity)}'>{html.escape(finding.severity)}</span></td>"
            f"<td>{html.escape(finding.title)}</td>"
            f"<td>{finding.points}</td>"
            f"<td>{html.escape(finding.evidence)}</td>"
            f"<td>{html.escape(finding.remediation)}</td>"
            "</tr>"
        )

    duration = (
        f"{report.metadata.duration_seconds:.3f}s"
        if report.metadata.duration_seconds is not None
        else "n/a"
    )

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>IronAudit Report</title>
  <style>
    :root {{
      --bg: #05080e;
      --panel: #0a101a;
      --text: #d7f7e9;
      --muted: #7ea893;
      --border: #173528;
      --good: #00e691;
      --warn: #ffb020;
      --bad: #ff5d73;
      --info: #28d7ff;
      --unsupported: #9ab4a7;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: "JetBrains Mono", "IBM Plex Mono", monospace; background: var(--bg); color: var(--text); }}
    .wrap {{ max-width: 1200px; margin: 20px auto; padding: 0 14px; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 14px; margin-bottom: 14px; }}
    .kpi {{ display: grid; grid-template-columns: repeat(6, minmax(80px, 1fr)); gap: 10px; }}
    .kpi > div {{ border: 1px solid var(--border); border-radius: 10px; padding: 8px; background: #0b1621; }}
    .label {{ color: var(--muted); font-size: .73rem; text-transform: uppercase; }}
    .value {{ font-size: 1.2rem; font-weight: 800; margin-top: 3px; }}
    table {{ width: 100%; border-collapse: collapse; min-width: 900px; }}
    th, td {{ border-bottom: 1px solid var(--border); padding: 8px; text-align: left; vertical-align: top; font-size: .88rem; }}
    th {{ color: var(--muted); text-transform: uppercase; font-size: .74rem; }}
    .table-wrap {{ overflow: auto; border: 1px solid var(--border); border-radius: 10px; }}
    .chip {{ border: 1px solid currentColor; border-radius: 999px; padding: 1px 7px; font-size: .75rem; font-weight: 800; }}
    .status-pass {{ color: var(--good); }}
    .status-fail {{ color: var(--bad); }}
    .status-warn {{ color: var(--warn); }}
    .status-info {{ color: var(--info); }}
    .status-unsupported {{ color: var(--unsupported); }}
    .sev-critical {{ color: #ff4d67; }}
    .sev-high {{ color: #ff7a5b; }}
    .sev-medium {{ color: #ffb020; }}
    .sev-low {{ color: #00d884; }}
    .sev-info {{ color: #28d7ff; }}
    @media (max-width: 800px) {{ .kpi {{ grid-template-columns: repeat(2, minmax(80px, 1fr)); }} }}
  </style>
</head>
<body>
  <div class='wrap'>
    <section class='card'>
      <h1 style='margin:0 0 8px;'>IronAudit Report</h1>
      <div style='color:var(--muted);'>Linux security posture auditor with scoring, findings, and remediation guidance.</div>
      <p style='margin:10px 0 0;'>Host: <strong>{html.escape(report.metadata.hostname)}</strong> | Distro: <strong>{html.escape(report.metadata.distro)}</strong> | Scanned: <strong>{html.escape(report.metadata.scanned_at)}</strong> | Duration: <strong>{duration}</strong></p>
      <p style='margin:8px 0 0;'>Score: <strong>{report.score}/100 ({html.escape(report.rating)})</strong> | Checks: {html.escape(', '.join(report.selected_checks))}</p>
    </section>

    <section class='card kpi'>
      <div><div class='label'>Pass</div><div class='value'>{counts.get('pass', 0)}</div></div>
      <div><div class='label'>Fail</div><div class='value'>{counts.get('fail', 0)}</div></div>
      <div><div class='label'>Warn</div><div class='value'>{counts.get('warn', 0)}</div></div>
      <div><div class='label'>Info</div><div class='value'>{counts.get('info', 0)}</div></div>
      <div><div class='label'>Unsupported</div><div class='value'>{counts.get('unsupported', 0)}</div></div>
      <div><div class='label'>Findings</div><div class='value'>{len(report.findings)}</div></div>
    </section>

    <section class='card'>
      <div class='table-wrap'>
        <table>
          <thead>
            <tr><th>Check</th><th>Status</th><th>Severity</th><th>Title</th><th>Pts</th><th>Evidence</th><th>Remediation</th></tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    </section>
  </div>
</body>
</html>
"""
