# History and Trend Tracking

IronAudit can persist snapshots of scan results and track score evolution.

## Save snapshots

```bash
ironaudit scan --save-history --label weekly-audit
# or
ironaudit history save --label weekly-audit
```

Profile-aware save:

```bash
ironaudit history save --profile server --label baseline
```

## List and inspect

```bash
ironaudit history list
ironaudit history show <snapshot_id>
ironaudit history show <snapshot_id> --json
ironaudit history show <snapshot_id> --md
ironaudit history show <snapshot_id> --html
ironaudit history show <snapshot_id> --sarif
```

## Trend and latest diff

```bash
ironaudit history trend
ironaudit history compare-latest
ironaudit history compare-latest --json
```

## Storage

- Default folder: `.ironaudit-history/`
- Override with env var: `IRONAUDIT_HISTORY_DIR`
