# Contributing to IronAudit

Thanks for contributing.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Before Opening a PR

Run locally:

```bash
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

## Contribution Rules

- Keep changes defensive-only (no offensive or exploit logic)
- Keep checks read-only and non-destructive
- Add or update tests for behavior changes
- Keep findings schema consistent
- Document new CLI flags and workflows

## Commit and PR Guidance

- Use clear commit messages (`feat:`, `fix:`, `docs:`, `chore:`)
- Scope PRs to one logical change
- Include impact summary and test evidence
