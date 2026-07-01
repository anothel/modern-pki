#!/usr/bin/env python3
"""Self-checks for the local verification wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    script = ROOT / "scripts" / "verify-local.ps1"
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
            "-List",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(result.stderr or result.stdout)
    for expected in (
        "python scripts\\validate-docs.py",
        "python scripts\\validate-service-contracts.py",
        "go test ./...",
        "go build ./cmd/modern-pki-service",
    ):
        if expected not in result.stdout:
            raise SystemExit(f"missing verify-local command: {expected}")
    print("verify-local tests ok")


if __name__ == "__main__":
    main()
