#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "security-baseline-scan.py"


def load_scanner():
    spec = importlib.util.spec_from_file_location("security_baseline_scan", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_finds_private_key_pem() -> None:
    scanner = load_scanner()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "leak.txt"
        path.write_text("-----BEGIN PRIVATE KEY-----\nabc\n", encoding="utf-8")  # secret-scan: allow
        findings = scanner.scan_root(Path(tmp))
    assert findings
    assert findings[0].kind == "private-key-pem"


def test_allows_documentation_placeholders() -> None:
    scanner = load_scanner()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "README.md"
        path.write_text(
            'MODERN_PKI_API_KEY_PEPPER = "<32+ chars random secret>"\n',
            encoding="utf-8",
        )
        findings = scanner.scan_root(Path(tmp))
    assert findings == []


def main() -> None:
    test_finds_private_key_pem()
    test_allows_documentation_placeholders()
    print("security baseline scan tests ok")


if __name__ == "__main__":
    main()
