from __future__ import annotations

import html
import json
from collections import Counter
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from ironaudit.engine import available_checks, run_scan
from ironaudit.exporters.html_exporter import to_html
from ironaudit.exporters.markdown_exporter import to_markdown
from ironaudit.models import ScanReport


@dataclass(slots=True)
class WebConfig:
    host: str = "127.0.0.1"
    port: int = 8765


def parse_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None


def render_home(report: ScanReport | None, include: str = "", exclude: str = "") -> str:
    checks = available_checks()
    checks_badges = "".join(f"<button type='button' class='badge'>{html.escape(c)}</button>" for c in checks)

    if report is None:
        report_html = """
        <div class='empty-state'>
          <h3>Ready to audit this host</h3>
          <p>No scan executed yet. Configure include/exclude filters, then run a scan.</p>
        </div>
        """
    else:
        report_html = render_report(report)

    query = urlencode({"checks": include, "exclude": exclude})
    api_link = f"/api/scan?{query}" if query else "/api/scan"
    md_link = f"/report.md?{query}" if query else "/report.md"
    html_link = f"/report.html?{query}" if query else "/report.html"

    return f"""<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>IronAudit | Security Posture Dashboard</title>
  <style>
    :root {{
      --bg: #05080e;
      --bg-overlay: #0a1424;
      --panel: #0a101a;
      --panel-2: #0f1724;
      --text: #d7f7e9;
      --muted: #7ea893;
      --accent: #00c46a;
      --accent-2: #00e691;
      --border: #173528;
      --good: #00e691;
      --warn: #ffb020;
      --bad: #ff5d73;
      --info: #28d7ff;
      --unsupported: #9ab4a7;
      --shadow: 0 18px 45px rgba(0, 0, 0, 0.45);
      --radius: 14px;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "JetBrains Mono", "IBM Plex Mono", "Cascadia Code", monospace;
      color: var(--text);
      background:
        radial-gradient(1100px 680px at -8% -8%, rgba(0, 228, 132, 0.12) 0%, transparent 55%),
        radial-gradient(900px 500px at 110% -10%, rgba(40, 215, 255, 0.09) 0%, transparent 60%),
        linear-gradient(180deg, #04070d 0%, var(--bg) 45%, #02050b 100%);
    }}
    .wrap {{ max-width: 1200px; margin: 32px auto 48px; padding: 0 16px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      padding: 18px;
      margin-bottom: 16px;
    }}
    .hero {{
      display: flex;
      justify-content: space-between;
      gap: 20px;
      align-items: center;
      background: linear-gradient(135deg, #07110d 0%, #0c1e18 55%, #0b2b1f 100%);
      color: #dffef1;
      overflow: hidden;
      position: relative;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      right: -80px;
      top: -80px;
      width: 260px;
      height: 260px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(0, 230, 145, 0.26), rgba(0, 230, 145, 0));
    }}
    .hero h1 {{ margin: 0 0 8px 0; font-size: 1.9rem; letter-spacing: -0.02em; }}
    .hero .tagline {{ margin: 0; color: #9ecab4; max-width: 800px; }}
    .hero-meta {{ font-size: 0.9rem; color: #79dca9; white-space: nowrap; }}
    .control-head {{ margin: 0 0 12px; font-size: 1.1rem; }}
    .row {{ display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }}
    .field {{ display: flex; flex-direction: column; gap: 6px; min-width: 260px; flex: 1; }}
    label {{ font-size: 0.84rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 700; }}
    input {{
      width: 100%;
      border: 1px solid var(--border);
      background: #0b1622;
      border-radius: 10px;
      padding: 10px 12px;
      font-size: 0.95rem;
      color: var(--text);
    }}
    input:focus {{
      outline: none;
      border-color: #00e691;
      box-shadow: 0 0 0 3px rgba(0, 230, 145, 0.22);
    }}
    .btn {{
      border: none;
      border-radius: 10px;
      padding: 11px 14px;
      cursor: pointer;
      font-weight: 700;
      letter-spacing: 0.01em;
      transition: transform .08s ease, filter .15s ease;
    }}
    .btn:active {{ transform: translateY(1px); }}
    .btn-primary {{
      background: linear-gradient(135deg, #00ab5b, var(--accent-2));
      color: #02120b;
      text-shadow: 0 1px 0 rgba(255, 255, 255, 0.2);
    }}
    .btn-primary:hover {{ filter: brightness(1.02); }}
    .checks {{ margin-top: 12px; display: flex; flex-wrap: wrap; gap: 6px; }}
    .badge {{
      border: 1px solid #214334;
      background: #0b1a14;
      color: #95f7c7;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.78rem;
      font-weight: 700;
    }}
    .resources {{ margin-top: 12px; display: flex; gap: 10px; flex-wrap: wrap; }}
    .resource-link {{
      text-decoration: none;
      color: #9bf8cc;
      font-weight: 700;
      font-size: 0.9rem;
      padding: 7px 10px;
      border-radius: 10px;
      border: 1px solid #214334;
      background: #0b1a14;
    }}
    .resource-link:hover {{ background: #0e241b; }}
    .empty-state {{ border: 1px dashed #285640; border-radius: 12px; padding: 22px; background: #0b1621; }}
    .empty-state h3 {{ margin: 0 0 6px 0; }}
    .empty-state p {{ margin: 0; color: var(--muted); }}
    .toolbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }}
    .search {{
      min-width: 260px;
      max-width: 360px;
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 9px 11px;
      background: #0b1622;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(6, minmax(110px, 1fr));
      gap: 10px;
      margin: 14px 0;
    }}
    .kpi {{
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #0b1621;
      padding: 10px;
    }}
    .kpi-label {{
      color: var(--muted);
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: .04em;
      margin-bottom: 6px;
      font-weight: 700;
    }}
    .kpi-value {{ font-size: 1.25rem; font-weight: 800; }}
    .report-meta {{
      display: grid;
      grid-template-columns: repeat(4, minmax(120px, 1fr));
      gap: 10px;
      margin-top: 8px;
    }}
    .meta-block {{ background: #0b1621; border: 1px solid var(--border); border-radius: 10px; padding: 9px; }}
    .meta-label {{ color: var(--muted); font-size: 0.74rem; text-transform: uppercase; font-weight: 700; }}
    .meta-value {{ margin-top: 4px; font-size: 0.92rem; font-weight: 700; word-break: break-word; }}
    .score-badge {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 1.05rem;
      font-weight: 800;
      padding: 8px 12px;
      border-radius: 999px;
      border: 1px solid #285640;
      background: #0b1a14;
    }}
    .score-dot {{ width: 10px; height: 10px; border-radius: 999px; background: currentColor; }}
    .score-hardened {{ color: #00e691; }}
    .score-acceptable {{ color: #28d7ff; }}
    .score-weak {{ color: #ffb020; }}
    .score-critical {{ color: #ff5d73; }}
    .table-wrap {{
      width: 100%;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: 12px;
      background: #08121d;
    }}
    table {{ width: 100%; border-collapse: collapse; min-width: 980px; font-size: 0.9rem; }}
    th, td {{ border-bottom: 1px solid #173528; padding: 9px 10px; text-align: left; vertical-align: top; }}
    th {{ position: sticky; top: 0; z-index: 1; background: #0d1b14; color: #91c8aa; font-size: 0.74rem; text-transform: uppercase; letter-spacing: .04em; }}
    tr:hover td {{ background: #0c1812; }}
    .chip {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 0.75rem;
      font-weight: 800;
      border: 1px solid currentColor;
    }}
    .status-pass {{ color: var(--good); }}
    .status-fail {{ color: var(--bad); }}
    .status-warn {{ color: var(--warn); }}
    .status-info {{ color: var(--info); }}
    .status-unsupported {{ color: var(--unsupported); }}
    .severity-critical {{ color: #ff4d67; }}
    .severity-high {{ color: #ff7a5b; }}
    .severity-medium {{ color: #ffb020; }}
    .severity-low {{ color: #00d884; }}
    .severity-info {{ color: #28d7ff; }}
    .mono {{ font-family: "IBM Plex Mono", "Cascadia Code", monospace; font-size: 0.86rem; }}
    .footer-note {{ margin-top: 10px; font-size: 0.84rem; color: var(--muted); }}
    .filters {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }}
    .filters select {{
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 10px;
      background: #0b1622;
      color: var(--text);
      min-width: 155px;
    }}
    .btn-subtle {{
      border: 1px solid var(--border);
      background: #0b1622;
      color: var(--text);
      border-radius: 10px;
      padding: 8px 10px;
      font-weight: 700;
      cursor: pointer;
    }}
    .btn-subtle:hover {{ background: #0e2219; }}
    .score-layout {{
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 12px;
      align-items: center;
      margin-top: 8px;
    }}
    .score-ring {{
      --score: 0;
      width: 110px;
      height: 110px;
      border-radius: 999px;
      background:
        radial-gradient(closest-side, #07100d 72%, transparent 73% 100%),
        conic-gradient(var(--accent-2) calc(var(--score) * 1%), #133126 0);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #9bf8cc;
      border: 1px solid #285640;
    }}
    .score-ring span {{ font-size: 1.15rem; }}
    .severity-grid {{
      display: grid;
      grid-template-columns: repeat(5, minmax(100px, 1fr));
      gap: 8px;
      margin-top: 10px;
    }}
    .sev-item {{
      border: 1px solid var(--border);
      border-radius: 10px;
      background: #0b1621;
      padding: 8px;
    }}
    .sev-name {{
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: .04em;
      color: var(--muted);
      font-weight: 700;
    }}
    .sev-val {{ font-size: 1.05rem; font-weight: 800; margin-top: 4px; }}
    .table-stats {{ margin-top: 8px; color: var(--muted); font-size: 0.84rem; }}
    .sort-btn {{
      border: none;
      background: transparent;
      cursor: pointer;
      font: inherit;
      color: inherit;
      font-weight: 800;
      letter-spacing: .03em;
      text-transform: uppercase;
      font-size: 0.72rem;
      padding: 0;
    }}
    .sort-btn:hover {{ color: var(--accent); }}
    .tight {{ max-width: 340px; }}
    .muted {{ color: var(--muted); }}
    @media (max-width: 700px) {{
      .row, .toolbar {{ flex-direction: column; align-items: stretch; }}
      .btn {{ width: 100%; }}
      .kpi-grid {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .report-meta {{ grid-template-columns: repeat(2, minmax(120px, 1fr)); }}
      .severity-grid {{ grid-template-columns: repeat(2, minmax(100px, 1fr)); }}
      .score-layout {{ grid-template-columns: 1fr; justify-items: start; }}
    }}
    @media (max-width: 460px) {{
      .report-meta, .kpi-grid {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>
  <div class='wrap'>
    <section class='card hero'>
      <div>
        <h1>&gt; IronAudit Security Console</h1>
        <p class='tagline'>Linux security posture auditor with scoring, findings, and remediation guidance.</p>
      </div>
      <div class='hero-meta mono'>LOCAL MODE // READ-ONLY AUDIT</div>
    </section>

    <section class='card'>
      <h2 class='control-head'>Scan Controls</h2>
      <form method='post' action='/scan'>
        <div class='row'>
          <div class='field'>
            <label for='checks'>Include checks (CSV)</label>
            <input id='checks' name='checks' placeholder='ssh,firewall,users' value='{html.escape(include)}' />
          </div>
          <div class='field'>
            <label for='exclude'>Exclude checks (CSV)</label>
            <input id='exclude' name='exclude' placeholder='updates' value='{html.escape(exclude)}' />
          </div>
          <button id='scan-btn' class='btn btn-primary' type='submit'>Run Security Scan</button>
        </div>
      </form>
      <div class='checks'>{checks_badges}</div>
      <div class='resources'>
        <a class='resource-link' href='{html.escape(api_link)}'>JSON API</a>
        <a class='resource-link' href='{html.escape(md_link)}'>Markdown Report</a>
        <a class='resource-link' href='{html.escape(html_link)}'>HTML Report</a>
      </div>
    </section>

    <section class='card'>
      <div class='toolbar'>
        <strong>Findings</strong>
        <div class='filters'>
          <input class='search' id='findings-search' type='search' placeholder='Filter findings by check, title, evidence...' />
          <select id='status-filter'>
            <option value='all'>All status</option>
            <option value='fail'>Fail</option>
            <option value='warn'>Warn</option>
            <option value='pass'>Pass</option>
            <option value='info'>Info</option>
            <option value='unsupported'>Unsupported</option>
          </select>
          <select id='severity-filter'>
            <option value='all'>All severity</option>
            <option value='critical'>Critical</option>
            <option value='high'>High</option>
            <option value='medium'>Medium</option>
            <option value='low'>Low</option>
            <option value='info'>Info</option>
          </select>
          <select id='sort-filter'>
            <option value='points:desc'>Sort by points (desc)</option>
            <option value='points:asc'>Sort by points (asc)</option>
            <option value='severity:desc'>Sort by severity (desc)</option>
            <option value='severity:asc'>Sort by severity (asc)</option>
            <option value='check:asc'>Sort by check (asc)</option>
            <option value='title:asc'>Sort by title (A-Z)</option>
          </select>
          <button type='button' id='reset-filters' class='btn-subtle'>Reset</button>
        </div>
      </div>
      {report_html}
      <p class='footer-note'>This dashboard executes local read-only checks and never applies automatic remediation.</p>
    </section>
  </div>
  <script>
    const form = document.querySelector("form[action='/scan']");
    const btn = document.getElementById("scan-btn");
    if (form && btn) {{
      form.addEventListener("submit", () => {{
        btn.textContent = "Scanning...";
        btn.setAttribute("disabled", "disabled");
      }});
    }}
    const search = document.getElementById("findings-search");
    const statusFilter = document.getElementById("status-filter");
    const severityFilter = document.getElementById("severity-filter");
    const sortFilter = document.getElementById("sort-filter");
    const resetBtn = document.getElementById("reset-filters");
    const severityOrder = {{ critical: 5, high: 4, medium: 3, low: 2, info: 1 }};

    function getRows() {{
      return Array.from(document.querySelectorAll("tbody tr.finding-row"));
    }}

    function applyFilters() {{
      const term = String(search?.value || "").toLowerCase().trim();
      const status = String(statusFilter?.value || "all");
      const severity = String(severityFilter?.value || "all");
      const rows = getRows();
      let visible = 0;
      rows.forEach((row) => {{
        const haystack = String(row.getAttribute("data-search") || "");
        const rowStatus = String(row.getAttribute("data-status") || "");
        const rowSeverity = String(row.getAttribute("data-severity") || "");
        const okTerm = !term || haystack.includes(term);
        const okStatus = status === "all" || rowStatus === status;
        const okSeverity = severity === "all" || rowSeverity === severity;
        const show = okTerm && okStatus && okSeverity;
        row.style.display = show ? "" : "none";
        if (show) visible += 1;
      }});
      const node = document.getElementById("table-visible-count");
      if (node) node.textContent = String(visible);
    }}

    function sortRows(spec) {{
      const [field, direction] = String(spec || "points:desc").split(":");
      const tbody = document.querySelector("tbody");
      if (!tbody) return;
      const dir = direction === "asc" ? 1 : -1;
      const rows = getRows();
      rows.sort((a, b) => {{
        const av = String(a.getAttribute("data-" + field) || "");
        const bv = String(b.getAttribute("data-" + field) || "");
        if (field === "points") {{
          return (Number(av) - Number(bv)) * dir;
        }}
        if (field === "severity") {{
          return ((severityOrder[av] || 0) - (severityOrder[bv] || 0)) * dir;
        }}
        return av.localeCompare(bv) * dir;
      }});
      rows.forEach((row) => tbody.appendChild(row));
    }}

    if (search) {{
      search.addEventListener("input", applyFilters);
    }}
    if (statusFilter) {{
      statusFilter.addEventListener("change", applyFilters);
    }}
    if (severityFilter) {{
      severityFilter.addEventListener("change", applyFilters);
    }}
    if (sortFilter) {{
      sortFilter.addEventListener("change", () => {{
        sortRows(sortFilter.value);
        applyFilters();
      }});
    }}
    if (resetBtn) {{
      resetBtn.addEventListener("click", () => {{
        if (search) search.value = "";
        if (statusFilter) statusFilter.value = "all";
        if (severityFilter) severityFilter.value = "all";
        if (sortFilter) sortFilter.value = "points:desc";
        sortRows("points:desc");
        applyFilters();
      }});
    }}

    document.querySelectorAll(".sort-btn").forEach((el) => {{
      el.addEventListener("click", () => {{
        const field = String(el.getAttribute("data-sort") || "");
        if (!field || !sortFilter) return;
        const current = String(sortFilter.value || "");
        const [currField, currDir] = current.split(":");
        const nextDir = currField === field && currDir === "desc" ? "asc" : "desc";
        sortFilter.value = field + ":" + nextDir;
        sortRows(sortFilter.value);
        applyFilters();
      }});
    }});

    if (document.querySelector("tbody tr.finding-row")) {{
      sortRows("points:desc");
      applyFilters();
    }}
    document.querySelectorAll(".badge").forEach((el) => {{
      el.addEventListener("click", () => {{
        const field = document.getElementById("checks");
        const value = (el.textContent || "").trim();
        if (!field || !value) return;
        const current = field.value.split(",").map((x) => x.trim()).filter(Boolean);
        if (!current.includes(value)) {{
          field.value = current.length ? current.concat([value]).join(",") : value;
        }}
      }});
    }});
  </script>
</body>
</html>
"""


def render_report(report: ScanReport) -> str:
    counts = Counter(f.status for f in report.findings)
    severity_counts = Counter(f.severity for f in report.findings)
    rating_css = f"score-{report.rating.lower()}"
    rows: list[str] = []
    for finding in report.findings:
        search_blob = " ".join(
            [
                finding.check_id,
                finding.status,
                finding.severity,
                finding.title,
                finding.category,
                finding.evidence,
                finding.remediation,
            ]
        ).lower()
        rows.append(
            f"""<tr class='finding-row' data-search='{html.escape(search_blob)}' data-check='{html.escape(finding.check_id)}' data-status='{html.escape(finding.status)}' data-severity='{html.escape(finding.severity)}' data-title='{html.escape(finding.title.lower())}' data-points='{finding.points}' data-category='{html.escape(finding.category.lower())}'>"""
            f"<td data-col='check' class='mono'>{html.escape(finding.check_id)}</td>"
            f"<td data-col='status'><span class='chip status-{html.escape(finding.status)}'>{html.escape(finding.status)}</span></td>"
            f"<td data-col='severity'><span class='chip severity-{html.escape(finding.severity)}'>{html.escape(finding.severity)}</span></td>"
            f"<td class='tight'><strong>{html.escape(finding.title)}</strong></td>"
            f"<td class='mono'>{finding.points}</td>"
            f"<td class='tight'>{html.escape(finding.evidence)}</td>"
            f"<td class='tight'>{html.escape(finding.remediation)}</td>"
            f"<td class='mono'>{html.escape(finding.category)}</td>"
            "</tr>"
        )

    return f"""
      <div class='score-layout'>
        <div class='score-ring' style='--score:{report.score};'><span>{report.score}</span></div>
        <div>
          <div class='score-badge {rating_css}'>
            <span class='score-dot'></span> Score: {report.score}/100 ({html.escape(report.rating)})
          </div>
          <div class='muted' style='margin-top:8px;'>Security rating calculated from fail/warn deductions. Higher is better.</div>
        </div>
      </div>
      <div class='severity-grid'>
        <div class='sev-item'><div class='sev-name'>Critical</div><div class='sev-val severity-critical'>{severity_counts.get('critical', 0)}</div></div>
        <div class='sev-item'><div class='sev-name'>High</div><div class='sev-val severity-high'>{severity_counts.get('high', 0)}</div></div>
        <div class='sev-item'><div class='sev-name'>Medium</div><div class='sev-val severity-medium'>{severity_counts.get('medium', 0)}</div></div>
        <div class='sev-item'><div class='sev-name'>Low</div><div class='sev-val severity-low'>{severity_counts.get('low', 0)}</div></div>
        <div class='sev-item'><div class='sev-name'>Info</div><div class='sev-val severity-info'>{severity_counts.get('info', 0)}</div></div>
      </div>
      <div class='report-meta'>
        <div class='meta-block'>
          <div class='meta-label'>Host</div>
          <div class='meta-value'>{html.escape(report.metadata.hostname)}</div>
        </div>
        <div class='meta-block'>
          <div class='meta-label'>Distribution</div>
          <div class='meta-value'>{html.escape(report.metadata.distro)}</div>
        </div>
        <div class='meta-block'>
          <div class='meta-label'>Scanned At</div>
          <div class='meta-value mono'>{html.escape(report.metadata.scanned_at)}</div>
        </div>
        <div class='meta-block'>
          <div class='meta-label'>Checks</div>
          <div class='meta-value mono'>{html.escape(", ".join(report.selected_checks))}</div>
        </div>
      </div>
      <div class='kpi-grid'>
        <div class='kpi'><div class='kpi-label'>Pass</div><div class='kpi-value status-pass'>{counts.get('pass', 0)}</div></div>
        <div class='kpi'><div class='kpi-label'>Fail</div><div class='kpi-value status-fail'>{counts.get('fail', 0)}</div></div>
        <div class='kpi'><div class='kpi-label'>Warn</div><div class='kpi-value status-warn'>{counts.get('warn', 0)}</div></div>
        <div class='kpi'><div class='kpi-label'>Info</div><div class='kpi-value status-info'>{counts.get('info', 0)}</div></div>
        <div class='kpi'><div class='kpi-label'>Unsupported</div><div class='kpi-value status-unsupported'>{counts.get('unsupported', 0)}</div></div>
        <div class='kpi'><div class='kpi-label'>Total Points</div><div class='kpi-value'>{sum(f.points for f in report.findings)}</div></div>
      </div>
      <div class='table-stats'>Showing <strong id='table-visible-count'>{len(report.findings)}</strong> / {len(report.findings)} findings</div>
      <div class='table-wrap'>
        <table>
          <thead>
            <tr>
              <th><button class='sort-btn' data-sort='check' type='button'>Check</button></th>
              <th><button class='sort-btn' data-sort='status' type='button'>Status</button></th>
              <th><button class='sort-btn' data-sort='severity' type='button'>Severity</button></th>
              <th><button class='sort-btn' data-sort='title' type='button'>Title</button></th>
              <th><button class='sort-btn' data-sort='points' type='button'>Pts</button></th>
              <th>Evidence</th><th>Remediation</th><th><button class='sort-btn' data-sort='category' type='button'>Category</button></th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows)}
          </tbody>
        </table>
      </div>
    """


class IronAuditHandler(BaseHTTPRequestHandler):
    server_version = "IronAuditWeb/0.1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._handle_home(parsed.query)
            return
        if parsed.path == "/api/checks":
            self._json_response({"checks": available_checks()})
            return
        if parsed.path == "/api/scan":
            self._handle_api_scan(parsed.query)
            return
        if parsed.path == "/report.md":
            self._handle_markdown(parsed.query)
            return
        if parsed.path == "/report.html":
            self._handle_html_report(parsed.query)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Route not found")

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/scan":
            self.send_error(HTTPStatus.NOT_FOUND, "Route not found")
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = parse_qs(body)
        include_raw = form.get("checks", [""])[0]
        exclude_raw = form.get("exclude", [""])[0]
        report = run_scan(include=parse_csv(include_raw), exclude=parse_csv(exclude_raw))

        content = render_home(report=report, include=include_raw, exclude=exclude_raw)
        self._html_response(content)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        _ = format, args
        return

    def _handle_home(self, query: str) -> None:
        params = parse_qs(query)
        include_raw = params.get("checks", [""])[0]
        exclude_raw = params.get("exclude", [""])[0]

        report = None
        if params.get("run", [""])[0] in {"1", "true", "yes"}:
            report = run_scan(include=parse_csv(include_raw), exclude=parse_csv(exclude_raw))

        content = render_home(report=report, include=include_raw, exclude=exclude_raw)
        self._html_response(content)

    def _handle_api_scan(self, query: str) -> None:
        params = parse_qs(query)
        include_raw = params.get("checks", [""])[0]
        exclude_raw = params.get("exclude", [""])[0]
        report = run_scan(include=parse_csv(include_raw), exclude=parse_csv(exclude_raw))
        self._json_response(report.to_dict())

    def _handle_markdown(self, query: str) -> None:
        params = parse_qs(query)
        include_raw = params.get("checks", [""])[0]
        exclude_raw = params.get("exclude", [""])[0]
        report = run_scan(include=parse_csv(include_raw), exclude=parse_csv(exclude_raw))
        payload = to_markdown(report)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(payload.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(payload.encode("utf-8"))

    def _handle_html_report(self, query: str) -> None:
        params = parse_qs(query)
        include_raw = params.get("checks", [""])[0]
        exclude_raw = params.get("exclude", [""])[0]
        report = run_scan(include=parse_csv(include_raw), exclude=parse_csv(exclude_raw))
        payload = to_html(report)
        self._html_response(payload)

    def _html_response(self, content: str) -> None:
        payload = content.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _json_response(self, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve_web(config: WebConfig) -> None:
    server = ThreadingHTTPServer((config.host, config.port), IronAuditHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
