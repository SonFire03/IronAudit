# Profiles

IronAudit supports scan profiles to tune check selection and risk weighting.

## Available profiles

- `workstation` (default): balanced profile for daily-use Linux hosts
- `server`: stricter weighting for network/auth/firewall risk on production-like servers
- `minimal`: focused baseline (critical core checks only)

## Usage

```bash
ironaudit scan --profile workstation
ironaudit scan --profile server
ironaudit scan --profile minimal
```

History save with profile:

```bash
ironaudit history save --profile server --label baseline
```

## Notes

- Profiles can adjust selected checks and point weighting.
- Effective profile is saved in report metadata (`scan_profile`).
