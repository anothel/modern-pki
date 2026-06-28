#!/usr/bin/env python3
"""Validate release evidence decisions and CI hooks."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/reference/release-evidence.md"
CI = ROOT / ".github/workflows/ci.yml"
RELEASE = ROOT / ".github/workflows/release.yml"

REQUIRED_DOC_TEXT = [
    "# Release Evidence",
    "## Tool Decisions",
    "## Release Artifacts",
    "## Compatibility Matrix",
    "## Required Evidence Per Release Candidate",
    "syft",
    "cosign",
    "govulncheck",
    "go vet ./...",
]

REQUIRED_CI_TEXT = [
    "python scripts/test_validate_release_evidence.py",
    "python scripts/validate-release-evidence.py",
    'go-version: "1.25.11"',
    "go vet ./...",
    "govulncheck@latest",
]

REQUIRED_RELEASE_TEXT = [
    "tags:",
    "contents: write",
    "id-token: write",
    'go-version: "1.25.11"',
    "go build -o ../dist/modern-pki-service",
    "cmake --build build-release --config Release",
    "syft scan dir:dist",
    "cosign sign-blob",
    "actions/upload-artifact",
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def require_text(path: Path, required: list[str]) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    text = path.read_text(encoding="utf-8")
    missing = [value for value in required if value not in text]
    if missing:
        fail(f"{path.relative_to(ROOT)} missing:\n" + "\n".join(missing))
    forbidden = [value for value in ("TBD", "TODO") if value in text]
    if forbidden:
        fail(f"{path.relative_to(ROOT)} contains placeholder text: {', '.join(forbidden)}")
    return text


def main() -> None:
    require_text(DOC, REQUIRED_DOC_TEXT)
    require_text(CI, REQUIRED_CI_TEXT)
    require_text(RELEASE, REQUIRED_RELEASE_TEXT)
    print("release evidence ok")


if __name__ == "__main__":
    main()
