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

---

## ENGLISH

### Overview
IronAudit is a defensive Linux hardening audit tool for local hosts. It runs non-destructive checks, produces structured findings with remediation guidance, computes a security score, and supports multiple report formats.

### Key Features
- Local Linux hardening checks
- Structured findings (`check_id`, severity, status, category, evidence, remediation, points)
- Score from 0 to 100 with rating bands
- Outputs: terminal, JSON, Markdown, HTML
- Web dashboard
- Baseline vs current report comparison
- History snapshots and trend tracking

### Defensive Scope
IronAudit is defensive-only. It does not perform exploitation, aggressive network scanning, or post-exploitation behavior.

### Quickstart
```bash
cd IronAudit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### CLI
```bash
ironaudit info
ironaudit version
ironaudit scan
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html
ironaudit scan --checks ssh,firewall,users
ironaudit scan --exclude updates
ironaudit scan --save-history --label baseline
```

### Web UI
```bash
ironaudit web
```
Routes:
- `/`
- `/api/scan`
- `/report.md`
- `/report.html`

### Compare Reports
```bash
ironaudit compare baseline.json current.json
ironaudit compare baseline.json current.json --json --output diff.json
```

### History
```bash
ironaudit history save --label weekly-audit
ironaudit history list
ironaudit history show <snapshot_id>
ironaudit history trend
ironaudit history compare-latest
```
Default path: `.ironaudit-history/` (override with `IRONAUDIT_HISTORY_DIR`).

### Scoring Model
- Start score: `100`
- `fail` and `warn` findings deduct points
- Final score is clamped to `0..100`

Rating bands:
- `90-100`: Hardened
- `70-89`: Acceptable
- `50-69`: Weak
- `0-49`: Critical

### Quality and Security
```bash
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

### Known Limits
- Some checks depend on local system commands (`ss`, `apt`, `systemctl`, etc.)
- Update check is currently Debian/Ubuntu focused
- Results may vary with privileges and containerized environments

### Disclaimer
IronAudit is for defensive auditing and educational use. It is read-only and does not auto-remediate.

---

## FRANCAIS

### Presentation
IronAudit est un outil defensif d'audit de durcissement Linux pour machine locale. Il execute des controles non destructifs, produit des findings structures avec remediation, calcule un score de securite, et supporte plusieurs formats de rapport.

### Fonctionnalites principales
- Checks de hardening Linux en local
- Findings structures (`check_id`, severite, statut, categorie, preuve, remediation, points)
- Score global de 0 a 100 avec niveau
- Sorties: terminal, JSON, Markdown, HTML
- Dashboard web
- Comparaison de rapports (baseline vs courant)
- Historique de snapshots et suivi de tendance

### Perimetre defensif
IronAudit est uniquement defensif. Il ne fait pas d'exploitation, pas de scan reseau agressif, pas de post-exploitation.

### Demarrage rapide
```bash
cd IronAudit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Commandes CLI
```bash
ironaudit info
ironaudit version
ironaudit scan
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html
ironaudit scan --checks ssh,firewall,users
ironaudit scan --exclude updates
ironaudit scan --save-history --label baseline
```

### Interface Web
```bash
ironaudit web
```
Routes:
- `/`
- `/api/scan`
- `/report.md`
- `/report.html`

### Comparer deux rapports
```bash
ironaudit compare baseline.json current.json
ironaudit compare baseline.json current.json --json --output diff.json
```

### Historique
```bash
ironaudit history save --label hebdo
ironaudit history list
ironaudit history show <snapshot_id>
ironaudit history trend
ironaudit history compare-latest
```
Chemin par defaut: `.ironaudit-history/` (surcharge avec `IRONAUDIT_HISTORY_DIR`).

### Modele de scoring
- Score initial: `100`
- Les findings `fail` et `warn` retirent des points
- Score final borne entre `0` et `100`

Niveaux:
- `90-100`: Hardened
- `70-89`: Acceptable
- `50-69`: Weak
- `0-49`: Critical

### Qualite et securite
```bash
pytest
ruff check .
mypy ironaudit
python scripts/privacy_guard.py
```

### Limites connues
- Certains checks dependent de commandes locales (`ss`, `apt`, `systemctl`, etc.)
- Le check updates est actuellement centre Debian/Ubuntu
- Les resultats peuvent varier selon privileges et environnements conteneurises

### Avertissement
IronAudit est fourni pour audit defensif et usage educatif. Outil en lecture seule, sans remediation automatique.

## License
MIT
