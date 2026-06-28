#!/usr/bin/env python3
"""Self-checks for service contract validation."""

from __future__ import annotations

import shutil
import subprocess
import sys
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-service-contracts.py"


def run_validator(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root)],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def copy_contract_inputs(dst: Path) -> None:
    files = [
        "service/internal/httpapi/server.go",
        "service/cmd/modern-pki-service/main.go",
        "service/internal/domain/errors.go",
        "service/README.md",
        "docs/reference/openapi.json",
        "docs/reference/api-errors.md",
    ]
    for name in files:
        target = dst / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)


def test_current_service_contracts_pass() -> None:
    result = run_validator(ROOT)
    assert result.returncode == 0, result.stderr + result.stdout


def test_missing_env_doc_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    readme = tmp_path / "service" / "README.md"
    readme.write_text(
        readme.read_text(encoding="utf-8").replace("`MODERN_PKI_ADDR`", "`MODERN_PKI_ADDR_DOC_DRIFT`", 1),
        encoding="utf-8",
    )

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "env vars used by service but missing from service/README.md table" in result.stderr


def test_missing_openapi_route_fails(tmp_path: Path) -> None:
    copy_contract_inputs(tmp_path)
    openapi = tmp_path / "docs" / "reference" / "openapi.json"
    data = json.loads(openapi.read_text(encoding="utf-8"))
    del data["paths"]["/identities"]
    openapi.write_text(json.dumps(data), encoding="utf-8")

    result = run_validator(tmp_path)

    assert result.returncode == 1
    assert "routes registered in service but missing from OpenAPI" in result.stderr


def main() -> None:
    test_current_service_contracts_pass()
    import tempfile

    with tempfile.TemporaryDirectory() as dirname:
        test_missing_env_doc_fails(Path(dirname))
    with tempfile.TemporaryDirectory() as dirname:
        test_missing_openapi_route_fails(Path(dirname))
    print("service contract validator tests ok")


if __name__ == "__main__":
    main()
