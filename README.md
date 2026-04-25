# IronAudit

Linux security posture auditor with scoring, findings, and remediation guidance.

IronAudit is a defensive Linux hardening audit tool for local hosts. It runs non-destructive checks, produces structured findings with remediation guidance, computes a security score, and supports multiple reporting formats for operations and security teams.

## Table of Contents

- [Why IronAudit](#why-ironaudit)
- [Core Capabilities](#core-capabilities)
- [Defensive Scope](#defensive-scope)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [CLI Usage](#cli-usage)
- [Web Dashboard](#web-dashboard)
- [Reporting](#reporting)
- [History and Trend Tracking](#history-and-trend-tracking)
- [Scoring Model](#scoring-model)
- [Supported Checks (MVP)](#supported-checks-mvp)
- [Quality and Security](#quality-and-security)
- [Known Limits](#known-limits)
- [Roadmap](#roadmap)
- [Disclaimer](#disclaimer)
- [License](#license)

## Why IronAudit

Security and infrastructure teams often need a fast baseline of host hardening posture before deeper remediation or compliance efforts. IronAudit is designed to provide that baseline with outputs that are easy to consume in terminal workflows, reports, and CI environments.

## Core Capabilities

- Local Linux hardening audit checks
- Structured findings with:
  - `check_id`, `severity`, `status`, `category`
  - evidence and remediation guidance
  - impact points
- Global score from 0 to 100 with rating bands
- Multi-format outputs:
  - terminal table
  - JSON
  - Markdown
  - HTML static report
- Web dashboard for browser-based review
- Baseline vs current report comparison
- Snapshot history with trend and latest comparison

## Defensive Scope

IronAudit is a **defensive auditor**. It is not an offensive tool and does not perform exploitation, aggressive network scanning, or post-exploitation behavior.

## Architecture

```text
ironaudit/
├── cli.py
├── engine.py
├── scoring.py
├── models.py
├── checks/
├── exporters/
├── history.py
├── compare.py
└── webapp.py
```

Design principles:

- read-only checks
- modular check modules
- graceful degradation on unsupported environments
- deterministic report schema for automation

## Quickstart

```bash
cd IronAudit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

First scan:

```bash
ironaudit scan
```

## CLI Usage

General:

```bash
ironaudit info
ironaudit version
```

Scan and exports:

```bash
ironaudit scan
ironaudit scan --json
ironaudit scan --md
ironaudit scan --html
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html
```

Check selection:

```bash
ironaudit scan --checks ssh,firewall,users
ironaudit scan --exclude updates
```

Report comparison:

```bash
ironaudit compare baseline.json current.json
ironaudit compare baseline.json current.json --json --output diff.json
```

## Web Dashboard

Start the local web interface:

```bash
ironaudit web
```

Custom host/port:

```bash
ironaudit web --host 0.0.0.0 --port 8080 --no-open-browser
```

Routes:

- `/` dashboard
- `/api/scan` JSON scan endpoint
- `/report.md` Markdown report endpoint
- `/report.html` HTML report endpoint

## Reporting

### JSON

Machine-readable output for pipelines and integrations.

### Markdown

Human-readable report for tickets, docs, and PR discussions.

### HTML

Portable static report with styled findings table and score summary.

## History and Trend Tracking

IronAudit can store local scan snapshots and track evolution over time.

Save snapshots:

```bash
ironaudit scan --save-history --label weekly-audit
# or
ironaudit history save --label baseline
```

List and inspect:

```bash
ironaudit history list
ironaudit history show <snapshot_id>
ironaudit history show <snapshot_id> --md
```

Trend and latest diff:

```bash
ironaudit history trend
ironaudit history compare-latest
ironaudit history compare-latest --json
```

Storage:

- default directory: `.ironaudit-history/`
- override with: `IRONAUDIT_HISTORY_DIR`

## Scoring Model

- Start score: `100`
- Findings in `fail` or `warn` deduct points
- Final score clamped to `[0, 100]`

Rating bands:

- `90–100`: Hardened
- `70–89`: Acceptable
- `50–69`: Weak
- `0–49`: Critical

Typical deduction examples:

- SSH root login enabled: `-20`
- SSH password authentication enabled: `-15`
- No active firewall: `-20`
- Unexpected UID 0 account: `-25`
- Sensitive world-writable entry: `-15`
- Many pending updates: `-5` to `-10`
- fail2ban missing: `-5`

## Supported Checks (MVP)

- SSH hardening posture
- Firewall activation detection (`ufw`, `nftables`, `iptables`)
- Exposed listening services and sensitive ports
- Users and privilege signals (`/etc/passwd`, UID 0, sudo/wheel)
- Dangerous permissions (world-writable and SUID/SGID inventory)
- Updates (Debian/Ubuntu path + unsupported handling)
- Basic auth hardening checks (fail2ban, PAM indicators)

## Quality and Security

Run quality suite locally:

```bash
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

CI includes:

- test/lint/type-check workflow
- privacy guard workflow for potential secrets/PII patterns

Privacy guard scans for patterns such as:

- private keys
- token-like secrets
- API key style strings
- email addresses
- local absolute home paths

Allowlist file:

- `.privacy-allowlist` for explicit, justified exceptions

## Known Limits

- Some checks depend on local commands (`ss`, `apt`, `systemctl`, etc.)
- Update enumeration is currently Debian/Ubuntu-focused
- Permission checks are bounded for performance in MVP
- Results can vary based on privileges and containerized environments

## Roadmap

- Additional distro-specific update checks (RHEL/Fedora/Arch)
- Profile/policy packs (CIS-aligned baseline sets)
- SARIF export for security tooling pipelines
- Snapshot analytics improvements (risk deltas by category)
- Optional signed report artifacts

## Disclaimer

IronAudit is provided for defensive security auditing and educational use. It performs read-only checks and does not apply automatic remediation.

## License

MIT
