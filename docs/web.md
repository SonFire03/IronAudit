# Web Dashboard

IronAudit provides a local web dashboard for interactive review.

## Run

```bash
ironaudit web
```

Custom bind:

```bash
ironaudit web --host 0.0.0.0 --port 8080 --no-open-browser
```

## Routes

- `/` interactive dashboard
- `/api/scan` JSON scan endpoint
- `/report.md` Markdown export endpoint
- `/report.html` HTML export endpoint

## Notes

- The dashboard triggers local read-only checks.
- It supports table filtering/sorting and report export links.
