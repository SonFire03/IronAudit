from __future__ import annotations

import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import NamedTuple


class CommandResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def run_command(command: list[str], timeout: int = 10) -> CommandResult:
    if not command:
        return CommandResult(returncode=127, stdout="", stderr="Empty command")
    if shutil.which(command[0]) is None:
        return CommandResult(returncode=127, stdout="", stderr=f"Command not found: {command[0]}")

    try:
        proc = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return CommandResult(proc.returncode, proc.stdout.strip(), proc.stderr.strip())
    except subprocess.TimeoutExpired:
        return CommandResult(returncode=124, stdout="", stderr=f"Command timed out: {' '.join(command)}")
    except OSError as exc:
        return CommandResult(returncode=1, stdout="", stderr=str(exc))


def safe_read_text(path: str | Path) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def parse_ssh_directives(text: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        parts = line.split()
        if len(parts) >= 2:
            key = parts[0].lower()
            value = " ".join(parts[1:]).strip()
            directives[key] = value
    return directives


def hostname() -> str:
    return socket.gethostname()


def detect_distro() -> str:
    os_release = safe_read_text("/etc/os-release")
    if not os_release:
        return os.uname().sysname

    values: dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    pretty = values.get("PRETTY_NAME")
    if pretty:
        return pretty
    return values.get("NAME", "Linux")


def distro_id_like() -> set[str]:
    os_release = safe_read_text("/etc/os-release")
    if not os_release:
        return set()
    values: dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"').lower()

    result = set()
    for key in ("ID", "ID_LIKE"):
        if key in values:
            result.update(values[key].split())
    return result
