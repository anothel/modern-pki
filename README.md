# modern-pki

`modern-pki` is an operational PKI lifecycle service project.

The goal is not only to generate certificates. The goal is to model and operate certificate lifecycle infrastructure: identity, enrollment, issuance policy, renewal, revocation, status publication, audit, notification, and ACME automation.

## Scope

Current implementation includes:

- C++ core CLI for CSR inspection, certificate issuance, CRL generation, and OCSP DER processing.
- Go HTTP service for lifecycle APIs and persistence.
- Identity, issuer, certificate profile, enrollment, approval, issuance, revocation, suspension, renewal, reissue, and expiration scan flows.
- CRL publication and OCSP response handling.
- Delegated OCSP responder registration and rotation.
- API key authentication with operator, write, and read scopes.
- Audit metadata, lifecycle outbox events, webhook notification endpoints, bounded retry, and dead-letter handling.
- ACME-shaped protocol adapter with account, order, authorization, HTTP-01 challenge, finalize, and certificate download flows.

See [docs/ROADMAP.md](docs/ROADMAP.md) for current priorities and remaining gaps.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `include/modern_pki` | C++ public headers for core PKI operations. |
| `src/core` | C++ core implementation. |
| `src/cli` | `modern-pki-core` CLI entrypoint used by the service. |
| `tests` | C++ core and CLI contract tests. |
| `service` | Go lifecycle API service. |
| `service/internal/store` | SQL and in-memory persistence. |
| `service/internal/lifecycle` | Lifecycle domain service, workers, outbox, notifications. |
| `service/internal/httpapi` | HTTP and ACME protocol adapter. |
| `docs/reference` | Stable operator/developer reference docs. |
| `docs/runbooks` | Manual verification and demo runbooks. |
| `scripts/acme-smoke` | Opt-in ACME client smoke harness scaffold. |

## Prerequisites

- Go 1.22+
- CMake 3.20+
- C++20 toolchain
- OpenSSL development libraries

On Windows, set `OPENSSL_ROOT_DIR` if CMake cannot find OpenSSL.

## Build And Test

Build and test the C++ core:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Test and build the Go service:

```powershell
cd service
go test ./...
go build ./cmd/modern-pki-service
```

## Run Locally

Build `modern-pki-core` first, then run the service with `MODERN_PKI_CORE_BIN` pointing at the CLI binary.

```powershell
cd service
$env:MODERN_PKI_ADDR = ":8080"
$env:MODERN_PKI_DB_DRIVER = "sqlite"
$env:MODERN_PKI_DB_DSN = "modern-pki.db"
$env:MODERN_PKI_CORE_BIN = "..\build\Debug\modern-pki-core.exe"
go run ./cmd/modern-pki-service
```

For local development, auth defaults to `dev` mode and accepts `X-Actor`.

For API-key mode:

```powershell
$env:MODERN_PKI_AUTH_MODE = "api_key"
$env:MODERN_PKI_BOOTSTRAP_API_KEY = "change-me"
$env:MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR = "ops-admin"
go run ./cmd/modern-pki-service
```

## Documentation

- [Service README](service/README.md): API behavior, configuration, ACME status, auth, workers, and operator endpoints.
- [Roadmap](docs/ROADMAP.md): completed work, next big work, backlog, and verification policy.
- [Audit metadata reference](docs/reference/audit-metadata.md): audit metadata fields and stable result codes.
- [Manual demo runbook](docs/runbooks/manual-demo.md): end-to-end local enrollment lifecycle demo.
- [ACME smoke harness](scripts/acme-smoke/README.md): local certbot-compatible smoke test scaffold; preflight works without certbot, live `-Run` requires certbot.

## Current Status

This is a lifecycle-service implementation in progress. Core lifecycle, profile policy, status publication, auth, audit, notifications, and ACME adapter foundations exist. The current next big work is running a live certbot smoke harness and converting compatibility gaps into tests.
