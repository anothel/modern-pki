#!/usr/bin/env python3
"""Tests for release evidence validation."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/validate-release-evidence.py"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    if "release evidence ok" not in result.stdout:
        raise SystemExit(f"unexpected validator output: {result.stdout!r}")
    print("release evidence validator tests ok")


if __name__ == "__main__":
    main()
