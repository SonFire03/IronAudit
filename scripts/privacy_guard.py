from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = ROOT / ".privacy-allowlist"

PATTERNS: dict[str, re.Pattern[str]] = {
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic_api_key": re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]"
    ),
    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "local_home_path": re.compile(r"/home/[A-Za-z0-9._-]+"),
}

# Keep CI signal high and avoid noisy false positives.
EMAIL_ALLOWLIST_SUFFIXES = ("@users.noreply.github.com",)
SKIP_DIR_FRAGMENTS = (
    ".git/",
    ".venv/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    "__pycache__/",
)
SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".pyc",
}


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {proc.stderr.strip()}")

    files: list[Path] = []
    for line in proc.stdout.splitlines():
        path = ROOT / line.strip()
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT).as_posix()
        if any(fragment in rel for fragment in SKIP_DIR_FRAGMENTS):
            continue
        if path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        files.append(path)
    return files


def load_allowlist() -> set[str]:
    if not ALLOWLIST_PATH.exists():
        return set()
    lines = [line.strip() for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines()]
    return {line for line in lines if line and not line.startswith("#")}


def main() -> int:
    allowlist = load_allowlist()
    violations: list[str] = []

    for file_path in tracked_files():
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        rel = file_path.relative_to(ROOT).as_posix()
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            for rule_name, pattern in PATTERNS.items():
                for match in pattern.finditer(raw_line):
                    secret = match.group(0)
                    if secret in allowlist:
                        continue
                    if rule_name == "email_address" and secret.endswith(EMAIL_ALLOWLIST_SUFFIXES):
                        continue
                    violations.append(
                        f"{rel}:{lineno}: {rule_name}: {secret[:90]}"
                    )

    if violations:
        print("Privacy guard failed: possible sensitive data detected.\n")
        for row in violations:
            print(row)
        print("\nIf this is intentional, add exact token/value to .privacy-allowlist with justification.")
        return 1

    print("Privacy guard passed: no sensitive patterns detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
