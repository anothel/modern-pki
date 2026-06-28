#!/usr/bin/env python3
"""Cheap service API/config/error documentation parity checks."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

ACME_PROTOCOL_PATHS = {
    "/acme/directory",
    "/acme/new-nonce",
    "/acme/new-account",
    "/acme/account/{id}",
    "/acme/new-order",
    "/acme/key-change",
    "/acme/order/{id}",
    "/acme/authz/{id}",
    "/acme/challenge/{id}",
    "/acme/order/{id}/finalize",
    "/acme/revoke-cert",
    "/acme/cert/{id}",
}

OPERATIONAL_PATHS = {
    "/debug/vars",
    "/healthz",
    "/readyz",
    "/version",
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def read_text(root: Path, path: str) -> str:
    return (root / path).read_text(encoding="utf-8")


def registered_routes(root: Path) -> set[tuple[str, str]]:
    files = [
        "service/internal/httpapi/server.go",
        "service/cmd/modern-pki-service/main.go",
    ]
    routes: set[tuple[str, str]] = set()
    pattern = re.compile(r'(?:[A-Za-z0-9_]+\.)?mux\.Handle(?:Func)?\("([A-Z]+) ([^"]+)"')
    for path in files:
        for method, route in pattern.findall(read_text(root, path)):
            if method in HTTP_METHODS:
                routes.add((method, route))
    return routes


def openapi_routes(root: Path) -> set[tuple[str, str]]:
    data = json.loads(read_text(root, "docs/reference/openapi.json"))
    routes: set[tuple[str, str]] = set()
    for path, operations in data.get("paths", {}).items():
        for method in operations:
            upper = method.upper()
            if upper in HTTP_METHODS:
                routes.add((upper, path))
    return routes


def openapi_expected_routes(root: Path) -> set[tuple[str, str]]:
    return {
        route
        for route in registered_routes(root)
        if route[1] not in ACME_PROTOCOL_PATHS and route[1] not in OPERATIONAL_PATHS
    }


def check_route_openapi_parity(root: Path) -> None:
    expected = openapi_expected_routes(root)
    documented = openapi_routes(root)
    missing = sorted(expected - documented)
    extra = sorted(documented - expected)
    messages = []
    if missing:
        messages.append(
            "routes registered in service but missing from OpenAPI:\n"
            + "\n".join(f"{method} {path}" for method, path in missing)
        )
    if extra:
        messages.append(
            "OpenAPI routes not registered in service:\n"
            + "\n".join(f"{method} {path}" for method, path in extra)
        )
    if messages:
        fail("\n\n".join(messages))


def used_env_vars(root: Path) -> set[str]:
    text = read_text(root, "service/cmd/modern-pki-service/main.go")
    pattern = re.compile(
        r'(?:envOrDefault|os\.Getenv|parse[A-Za-z0-9_]*Env)\("'
        r"(MODERN_PKI_[A-Z0-9_]+)"
        r'"'
    )
    return set(pattern.findall(text))


def documented_env_vars(root: Path) -> set[str]:
    text = read_text(root, "service/README.md")
    return set(re.findall(r"^\|\s*`(MODERN_PKI_[A-Z0-9_]+)`\s*\|", text, flags=re.MULTILINE))


def check_env_doc_parity(root: Path) -> None:
    used = used_env_vars(root)
    documented = documented_env_vars(root)
    missing = sorted(used - documented)
    extra = sorted(documented - used)
    messages = []
    if missing:
        messages.append(
            "env vars used by service but missing from service/README.md table:\n"
            + "\n".join(missing)
        )
    if extra:
        messages.append(
            "env vars documented in service/README.md table but not used by service:\n"
            + "\n".join(extra)
        )
    if messages:
        fail("\n\n".join(messages))


def mapped_public_errors(root: Path) -> set[str]:
    text = read_text(root, "service/internal/httpapi/server.go")
    match = re.search(r"func publicErrorMessage\(err error\) string \{(?P<body>.*?)\n\}", text, flags=re.S)
    if not match:
        fail("publicErrorMessage function not found")
    return set(re.findall(r"errors\.Is\(err,\s*domain\.(Err[A-Za-z0-9]+)\)", match.group("body")))


def domain_errors(root: Path) -> set[str]:
    text = read_text(root, "service/internal/domain/errors.go")
    return set(re.findall(r"\b(Err[A-Za-z0-9]+)\s*=\s*errors\.New", text))


def documented_http_errors(root: Path) -> set[str]:
    text = read_text(root, "docs/reference/api-errors.md")
    match = re.search(r"## HTTP Mapping(?P<body>.*?)## ACME Problem Types", text, flags=re.S)
    if not match:
        fail("HTTP Mapping section not found in docs/reference/api-errors.md")
    return set(re.findall(r"^\|\s*`(Err[A-Za-z0-9]+)`\s*\|", match.group("body"), flags=re.MULTILINE))


def check_error_doc_parity(root: Path) -> None:
    mapped = mapped_public_errors(root)
    documented = documented_http_errors(root)
    known = domain_errors(root)
    messages = []
    missing = sorted(mapped - documented)
    unknown_docs = sorted(documented - known)
    if missing:
        messages.append(
            "public errors mapped in service but missing from api-errors.md:\n"
            + "\n".join(missing)
        )
    if unknown_docs:
        messages.append(
            "api-errors.md documents unknown domain errors:\n"
            + "\n".join(unknown_docs)
        )
    if "ACME bad nonce" not in read_text(root, "docs/reference/api-errors.md"):
        messages.append("api-errors.md missing ACME bad nonce mapping")
    if "unknown error" not in read_text(root, "docs/reference/api-errors.md"):
        messages.append("api-errors.md missing unknown error mapping")
    if messages:
        fail("\n\n".join(messages))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    check_route_openapi_parity(root)
    check_env_doc_parity(root)
    check_error_doc_parity(root)
    print("service contracts ok")


if __name__ == "__main__":
    main()
