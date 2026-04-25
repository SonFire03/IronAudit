# IronAudit

Linux security posture auditor with scoring, findings, and remediation guidance.

[![Python](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Typer](https://img.shields.io/badge/CLI-Typer-009688)](https://typer.tiangolo.com/)
[![Rich](https://img.shields.io/badge/UI-Rich-FAAD14)](https://github.com/Textualize/rich)
[![Pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)](https://pytest.org/)
[![Ruff](https://img.shields.io/badge/lint-Ruff-D7FF64)](https://docs.astral.sh/ruff/)
[![mypy](https://img.shields.io/badge/type%20check-mypy-2A6DB2)](https://mypy-lang.org/)
[![CI](https://img.shields.io/github/actions/workflow/status/SonFire03/IronAudit/ci.yml?branch=main&label=ci)](https://github.com/SonFire03/IronAudit/actions/workflows/ci.yml)
[![Privacy Guard](https://img.shields.io/github/actions/workflow/status/SonFire03/IronAudit/privacy-guard.yml?branch=main&label=privacy%20guard)](https://github.com/SonFire03/IronAudit/actions/workflows/privacy-guard.yml)
[![License](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

IronAudit is a defensive, local Linux hardening auditor. It runs read-only checks, produces actionable findings, computes a score, and exports reports for operations and security workflows.

## Why IronAudit

- Fast baseline for Linux host security posture
- Structured findings with remediation guidance
- Consistent scoring for tracking progress over time
- Defensive-only behavior (no exploit or post-exploitation logic)

## Core Features

- Linux checks: SSH, firewall, services exposure, users/sudo, permissions, updates, auth
- Findings model: severity, status, category, evidence, remediation, points
- Score/rating model: `0..100` with posture bands
- Outputs: terminal, JSON, Markdown, HTML
- Local web dashboard
- JSON report comparison (`baseline` vs `current`)
- Snapshot history (`save/list/show/trend/compare-latest`)

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
ironaudit scan
```
<img width="1267" height="692" alt="image" src="https://github.com/user-attachments/assets/9c42c07a-68b5-4c4b-ad23-631203187d02" />


## Validated Commands

```bash
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

Current local status in this repo:
- tests: pass
- lint: pass
- type-check: pass
- privacy guard: pass

## Common Workflows

```bash
# Export reports
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html

# Narrow scope
ironaudit scan --checks ssh,firewall,users
ironaudit scan --exclude updates

# Compare two JSON reports
ironaudit compare baseline.json current.json

# Use web dashboard
ironaudit web
```

## Documentation

- English docs (feature details):
  - [Web Dashboard](docs/web.md)
  - [History & Trend](docs/history.md)
  - [Report Compare](docs/compare.md)
- Documentation francaise: [README.fr.md](docs/README.fr.md)
- Contribution and governance:
  - [Contributing](CONTRIBUTING.md)
  - [Security Policy](SECURITY.md)
  - [Code of Conduct](CODE_OF_CONDUCT.md)

## Current Limits

- Some checks require local commands (`ss`, `apt`, `systemctl`, etc.)
- Update enumeration is currently Debian/Ubuntu focused
- Results can vary with privileges and containerized environments

## Defensive Disclaimer

IronAudit is provided for defensive auditing and educational use. It performs read-only checks and does not auto-remediate.

## License

MIT
