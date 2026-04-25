# Compare Reports

Use report comparison to identify newly introduced risks and resolved issues.

## Command

```bash
ironaudit compare baseline.json current.json
```

JSON output:

```bash
ironaudit compare baseline.json current.json --json --output diff.json
```

## Output includes

- `before_score`
- `after_score`
- `score_delta`
- `new_risks`
- `resolved_risks`

Only `fail` and `warn` findings are considered in risk delta.
