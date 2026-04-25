# IronAudit

Linux security posture auditor with scoring, findings, and remediation guidance.

IronAudit is a defensive CLI that audits a local Linux host for basic hardening posture. It evaluates common security controls, assigns a score out of 100, and emits actionable findings.

## Why this project exists

Operational teams often need a fast, local, and readable baseline security audit before deeper hardening or compliance work. IronAudit focuses on practical checks and clear remediation guidance, without offensive behavior.

## Features

- Local Linux hardening checks (SSH, firewall, exposed services, users/sudo, permissions, updates, auth)
- Structured findings with severity, status, evidence, and remediation
- Global score and rating:
  - 90-100: Hardened
  - 70-89: Acceptable
  - 50-69: Weak
  - 0-49: Critical
- Terminal output with Rich
- JSON export
- Markdown export
- HTML export (static report)
- Local Web UI for browser-based usage
- Check filtering (`--checks`, `--exclude`)
- Report comparison (baseline vs current JSON reports)

## Defensive scope

IronAudit is a defensive posture auditor. It does not perform exploitation, aggressive network scanning, or post-exploitation actions.

## Installation

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development tools:

```bash
pip install -e .[dev]
```

## Usage

```bash
ironaudit info
ironaudit version
ironaudit scan
ironaudit scan --json
ironaudit scan --md
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html
ironaudit scan --save-history --label weekly-audit
ironaudit scan --checks ssh,firewall,users
ironaudit scan --exclude updates
ironaudit web
ironaudit web --host 0.0.0.0 --port 8080 --no-open-browser
ironaudit compare baseline.json current.json
ironaudit compare baseline.json current.json --json --output diff.json
ironaudit history save --label baseline
ironaudit history list
ironaudit history trend
ironaudit history compare-latest
```

Web UI routes:

- `/` browser dashboard with scan form and findings table
- `/api/scan` JSON report endpoint
- `/report.md` Markdown report endpoint
- `/report.html` static HTML report endpoint

## History snapshots

IronAudit can persist local scan snapshots for trend tracking:

- `ironaudit history save` runs a scan and stores a JSON snapshot
- `ironaudit history list` lists saved snapshots
- `ironaudit history show <snapshot_id>` renders a snapshot
- `ironaudit history trend` shows score evolution
- `ironaudit history compare-latest` compares the two newest snapshots

By default snapshots are stored in `.ironaudit-history/`.  
Override with environment variable `IRONAUDIT_HISTORY_DIR`.

## Example output

```text
IronAudit Findings
- ssh        fail  high    SSH password authentication enabled   15
- firewall   pass  info    UFW firewall is active                0
...
Score: 78/100 (Acceptable)
```

## Scoring model

- Score starts at 100
- Findings in `fail` or `warn` state can deduct points
- Score is clamped between 0 and 100

Default deduction examples:

- SSH root login enabled: -20
- SSH password auth enabled: -15
- No active firewall: -20
- Unexpected UID 0 account: -25
- Sensitive world-writable path: -15
- Many pending updates: -5 to -10
- fail2ban missing: -5

## Limits

- Some checks depend on local commands (`ss`, `apt`, `systemctl`, etc.)
- Update check is currently Debian/Ubuntu-focused; other distros return `unsupported`
- Permission inventory is intentionally bounded for MVP performance
- Results can vary depending on local privileges and containerized environments

## Roadmap

- Add distro-specific patch checks (RHEL/Fedora/Arch)
- Add CIS-aligned check profiles
- Add SARIF and HTML exporters
- Add machine-readable policy profiles (YAML)
- Add trend comparison between scan snapshots

## Quality

```bash
pytest
ruff check .
mypy ironaudit
```

## Disclaimer

This tool is provided for defensive security auditing and educational use. It performs read-only local checks and does not apply remediation automatically in v0.1.

## License

MIT
