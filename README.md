# IronAudit

Lightweight local Linux security posture auditor focused on clear findings and report-ready output.

IronAudit runs safe read-only checks on a Linux host, maps results to severity-based findings, computes a capped risk score (`0..100`), and exports reports for remediation tracking.

## Who It Is For

- Sysadmins and platform engineers maintaining Linux hosts
- Security teams that want fast, local, explainable posture snapshots
- Consultants preparing defensive hardening reports
- Open-source users who prefer Python CLI workflows over heavyweight scanners

## Quick Screenshots

> TODO: Replace placeholders in `docs/screenshots/` with real captures from your environment.

![Terminal scan](docs/screenshots/terminal-scan.png)
![HTML report](docs/screenshots/html-report.png)
![PDF report](docs/screenshots/pdf-report.png)
![Dashboard](docs/screenshots/dashboard.png)
![Compare reports](docs/screenshots/compare-reports.png)

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ironaudit scan
```

## Example Output

```text
Score: 52/100 (Weak)
Scoring breakdown: base 100 | deduction 48 | final 52 |
critical 0/80 (raw 0); high 30/30 (raw 54); medium 18/18 (raw 26); low 0/8 (raw 0); info 0/0 (raw 0)
```

## Report Export Commands

```bash
# Terminal table output
ironaudit scan

# JSON report
ironaudit scan --json --output report.json

# Markdown report
ironaudit scan --md --output report.md

# HTML report
ironaudit scan --html --output report.html

# PDF report
ironaudit scan --pdf --output report.pdf

# SARIF report (optional CI/security tooling integration)
ironaudit scan --sarif --output report.sarif
```

## Sample Reports

- [JSON sample](docs/samples/sample-report.json)
- [HTML sample](docs/samples/sample-report.html)
- [PDF sample](docs/samples/sample-report.pdf)

## Scoring Model (Strict But Explainable)

IronAudit starts at a **base score of 100** and only deducts points from `warn` and `fail` findings.

Severity buckets use capped deductions to keep scoring credible for professional reporting:

- `info`: cap `0` (informational findings never reduce score)
- `low`: cap `8` (small total impact)
- `medium`: cap `18` (moderate total impact)
- `high`: cap `30` (large impact)
- `critical`: cap `80` (very strong impact)

Final score formula:

- `final = clamp(100 - sum(capped_deductions), 0, 100)`

Rating labels:

- `90-100`: Excellent
- `75-89`: Good
- `60-74`: Fair
- `40-59`: Weak
- `20-39`: Poor
- `0-19`: Critical

Why caps exist:

- Repeated low/medium findings are still visible in findings, but do not automatically collapse the score to `0`.
- High/critical findings remain heavily weighted, so dangerous configurations still produce poor or critical ratings.

## Feature List

- Local read-only Linux posture checks
- Structured findings (`severity`, `status`, `evidence`, `remediation`, `points`)
- Profile-aware scanning (`workstation`, `server`, `minimal`)
- Capped severity-based scoring with detailed breakdown
- Export formats: terminal, JSON, Markdown, HTML, PDF, SARIF
- Report comparison (`ironaudit compare`) and local history snapshots

## What It Is / What It Is Not

What it is:

- Defensive host posture auditor
- Lightweight Python CLI tool for quick, explainable assessments
- Report-oriented workflow for hardening follow-up

What it is not:

- Not a vulnerability exploitation framework
- Not an aggressive network scanner
- Not a replacement for enterprise VM suites or compliance platforms

## Positioning vs Existing Tools

IronAudit is intentionally lightweight and local-first. It complements, rather than replaces:

- Lynis (broad host auditing and hardening guidance)
- OpenSCAP (compliance and policy content ecosystem)
- Nessus/OpenVAS (network vulnerability management)

Use IronAudit when you need fast, Python-based, report-friendly Linux posture checks with transparent scoring logic.

## Roadmap

- Expand defensive checks with stronger evidence quality
- Improve report UX and remediation prioritization
- Add more sample reports and screenshot coverage
- Improve baseline comparison workflows
- Strengthen docs for operators and contributors

## Feedback Wanted

IronAudit is an early open-source project and feedback is welcome on:

- Check coverage and false positives
- Scoring model and rating credibility
- Report usefulness (terminal/HTML/PDF/JSON)
- CLI and overall user experience

## Contributing

Contributions are welcome. For safe, consistent changes:

```bash
source .venv/bin/activate
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

Please keep contributions defensive, transparent, and operationally useful.

## Defensive-Only Disclaimer

IronAudit is for authorized defensive security auditing on systems you own or are explicitly permitted to assess. It does not include exploit payloads or offensive automation.

## License

MIT
