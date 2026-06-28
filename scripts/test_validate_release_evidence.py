#!/usr/bin/env python3
"""Tests for release evidence validation."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"


def require_release_workflow() -> None:
    if not RELEASE_WORKFLOW.is_file():
        raise SystemExit("missing release workflow: .github/workflows/release.yml")
    text = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    required = [
        "on:",
        "tags:",
        "contents: write",
        "id-token: write",
        'go-version: "1.25.11"',
        "cmake --build build-release --config Release",
        "go build -o ../dist/modern-pki-service",
        "syft scan dir:dist",
        "cosign sign-blob",
        "actions/upload-artifact",
    ]
    missing = [value for value in required if value not in text]
    if missing:
        raise SystemExit(".github/workflows/release.yml missing:\n" + "\n".join(missing))


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
    require_release_workflow()
    print("release evidence validator tests ok")


if __name__ == "__main__":
    main()
