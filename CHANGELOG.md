# Changelog

## 0.2.4 - 2026-05-16

- Added `ironaudit scan --summary` for concise terminal output in CI and automation logs
- Added `ironaudit scan --quiet` to suppress remediation hints in default terminal output
- Improved remediation prioritization in terminal, Markdown, and HTML outputs
- Synced project version metadata (`pyproject.toml`, package `__version__`) with release history
- Improved README quality: badges, CLI summary example, comparison section cleanup
- Updated French documentation with PDF/SARIF export examples and summary mode

## 0.2.3 - 2026-05-05

- Improved README safety documentation with an explicit Safety Model section
- Added clearer comparison with existing tools (Lynis, CIS Benchmarks, OpenSCAP)
- Expanded limitations documentation (scope, non-certification, human review, authorization requirement)
- Added responsible-usage warning near Quickstart
- Refined project positioning for transparent, defensive public feedback preparation

## 0.2.2 - 2026-05-04

- Reworked README for faster project understanding and clearer defensive positioning
- Clarified tool scope: lightweight local Linux posture auditor, not a replacement for Lynis/OpenSCAP/Nessus/OpenVAS
- Added scoring documentation with base score, severity caps, deductions, rating labels, and rationale
- Documented full CLI report outputs (terminal, JSON, Markdown, HTML, PDF, SARIF)
- Added sample report links for JSON/HTML/PDF artifacts
- Added screenshot section and repository screenshot placeholders under `docs/screenshots/`
- Added Reddit-ready feedback section inviting input on checks, scoring, reports, and UX
- Prepared repository messaging for public open-source feedback

## 0.2.0 - 2026-04-25

- Added scan profiles with weighted scoring (`workstation`, `server`, `minimal`)
- Added SARIF export support (`ironaudit scan --sarif` and history snapshot SARIF output)
- Added SARIF web endpoint (`/report.sarif`) and dashboard link
- Added profile metadata in reports (`scan_profile`)
- Added profile-aware scanning in history save workflow
- Extended test coverage for profiles and SARIF exporter

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
