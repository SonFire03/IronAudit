# IronAudit (Documentation Francaise)

IronAudit est un auditeur defensif de posture de securite Linux avec scoring, findings et recommandations de remediation.

## Resume

IronAudit execute des checks locaux non destructifs sur une machine Linux, puis produit:

- des findings structures
- un score global sur 100
- des exports terminal / JSON / Markdown / HTML
- un dashboard web local

## Installation rapide

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Commandes principales

```bash
ironaudit info
ironaudit version
ironaudit scan
ironaudit scan --summary
ironaudit scan --json --output report.json
ironaudit scan --md --output report.md
ironaudit scan --html --output report.html
ironaudit scan --pdf --output report.pdf
ironaudit scan --sarif --output report.sarif
ironaudit web
```

## Comparaison de rapports

```bash
ironaudit compare baseline.json current.json
ironaudit compare baseline.json current.json --json --output diff.json
```

## Historique et tendance

```bash
ironaudit history save --label baseline
ironaudit history list
ironaudit history show <snapshot_id>
ironaudit history trend
ironaudit history compare-latest
```

## Limites actuelles

- Certains checks dependent de commandes locales (`ss`, `apt`, `systemctl`, etc.)
- Le check updates est centre Debian/Ubuntu
- Les resultats varient selon privileges et conteneurisation

## Positionnement defensif

IronAudit est un outil defensif (lecture seule): pas d'exploitation, pas de post-exploitation, pas de remediation automatique.
