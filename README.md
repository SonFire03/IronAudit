# IronAudit Pro

Professional local Linux security audit tool for authorized defensive assessments.

IronAudit Pro runs on a Linux host, executes safe read-only checks, computes a security score from `0` to `100`, and exports clean client-ready reports.

## V0.1 Scope

- Local audit tool (not SaaS)
- Defensive and authorized use only
- No exploit code
- No aggressive scanning
- Maintainable CLI-first workflow

## Core Checks

- system information
- Linux distribution and kernel
- pending updates
- firewall status
- SSH configuration
- open listening ports
- enabled services
- risky permissions

## Scoring and Severity

- Global score: `0..100`
- Severity levels: `critical`, `high`, `medium`, `low`, `info`
- Findings include: status, evidence, remediation, and scoring points

## Export Formats

- JSON
- HTML (premium client-facing template)
- PDF
- Additional existing formats: Markdown, SARIF

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
ironaudit scan
```

## Usage

```bash
# Terminal output
ironaudit scan

# Client-ready exports
ironaudit scan --json --output report.json
ironaudit scan --html --output report.html
ironaudit scan --pdf --output report.pdf

# Scope control
ironaudit scan --checks system,ssh,firewall,ports
ironaudit scan --exclude updates
ironaudit scan --profile server
```

## Sample Reports

- `docs/samples/sample-report.json`
- `docs/samples/sample-report.html`
- `docs/samples/sample-report.pdf`

## Quality Gates

```bash
source .venv/bin/activate
pytest
ruff check .
mypy ironaudit
```

## CI

GitHub Actions CI is included in `.github/workflows/ci.yml` and runs tests, lint, and type checks.

## Safe-Use Disclaimer

IronAudit Pro is intended for defensive security auditing on systems you own or are explicitly authorized to assess. Use responsibly and in compliance with applicable law and policy.

## License

MIT
