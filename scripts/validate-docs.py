#!/usr/bin/env python3
"""Cheap docs-as-code checks for the PKI documentation baseline."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "docs/ROADMAP.md",
    "docs/architecture/pki-context.md",
    "docs/architecture/ca-hierarchy.md",
    "docs/architecture/issuance-flow.md",
    "docs/architecture/renewal-flow.md",
    "docs/architecture/revocation-flow.md",
    "docs/policy/certificate-profiles.md",
    "docs/policy/algorithm-policy.md",
    "docs/policy/cp-cps-map.md",
    "docs/operations/issuance-runbook.md",
    "docs/operations/renewal-runbook.md",
    "docs/operations/revocation-runbook.md",
    "docs/operations/mass-revocation-plan.md",
    "docs/operations/key-ceremony.md",
    "docs/operations/backup-restore-runbook.md",
    "docs/security/threat-model.md",
    "docs/security/audit-log-schema.md",
    "docs/adr/0001-ca-backend-selection.md",
    "docs/adr/0002-acme-adoption.md",
    "docs/adr/0003-hsm-kms-strategy.md",
    "docs/reference/improvement-analysis-alignment.md",
    "docs/reference/openapi.json",
]


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def check_required_files() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).is_file()]
    if missing:
        fail("missing required docs:\n" + "\n".join(missing))


def check_openapi_json() -> None:
    with (ROOT / "docs/reference/openapi.json").open(encoding="utf-8") as fh:
        json.load(fh)


def check_readme_links() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    links = re.findall(r"\]\(([^)#][^)]+)\)", readme)
    missing = []
    for link in links:
        if "://" in link or link.startswith("mailto:"):
            continue
        target = (ROOT / link).resolve()
        if not target.exists():
            missing.append(link)
    if missing:
        fail("README links point to missing files:\n" + "\n".join(missing))


def check_license_state() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "No `LICENSE` file has been selected yet" in readme or "all rights are reserved" in readme:
        fail("README still says license is undecided")
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "Apache License" not in license_text or "Version 2.0" not in license_text:
        fail("LICENSE is not Apache-2.0 text")


def main() -> None:
    check_required_files()
    check_openapi_json()
    check_readme_links()
    check_license_state()
    print("docs ok")


if __name__ == "__main__":
    main()
