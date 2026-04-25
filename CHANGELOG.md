# Changelog

## 0.1.0 - 2026-04-25

- Initial MVP release
- Added Linux hardening checks: SSH, firewall, services, users, permissions, updates, auth
- Added scoring/rating engine and structured findings model
- Added JSON and Markdown exporters
- Added Typer CLI commands: scan, info, version
- Added pytest test suite and lint/type-check configuration
- Added web dashboard with dark terminal theme and advanced filtering/sorting
- Added HTML static report exporter and `/report.html` web route
- Added `ironaudit compare` command for baseline vs current report analysis
- Added `ironaudit history` command group (save/list/show/trend/compare-latest)
- Added scan duration metadata and report loading/parsing helpers
