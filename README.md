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

See [docs/ROADMAP.md](docs/ROADMAP.md) for future work and
[Release readiness action plan](docs/reference/release-readiness-action-plan.md)
for the current execution order derived from the uploaded analysis reports.

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

## Quickstart Smoke Checklist

Use this deterministic checklist before trusting a local change or release
candidate. Expected output is shown after each command.

```powershell
python scripts\validate-docs.py
# docs ok

python scripts\test_webhook_receiver_verification.py
# webhook receiver verification tests passed: 7

python scripts\test_validate_service_contracts.py
# service contract validator tests ok

python scripts\validate-service-contracts.py
# service contracts ok

python scripts\test_security_baseline_scan.py
# security baseline scan tests ok

python scripts\security-baseline-scan.py
# secret baseline scan ok

cd service
go test ./...
# all listed packages exit ok

go build ./cmd/modern-pki-service
# exit 0
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
$env:MODERN_PKI_API_KEY_PEPPER = "local-dev-pepper-0123456789abcdef"
go run ./cmd/modern-pki-service
```

## Documentation

- [Service README](service/README.md): API behavior, configuration, ACME status, auth, workers, and operator endpoints.
- [Roadmap](docs/ROADMAP.md): future-only priorities, defer/delete rules, and remaining risk areas.
- [Changelog](CHANGELOG.md): release-candidate notes, verification baseline, and known gaps.
- [Release readiness action plan](docs/reference/release-readiness-action-plan.md): current grouped execution plan from the 2026-06-28 analysis.
- [Security policy](SECURITY.md): reporting, supported status, production expectations, known constraints, and disclosure process.
- [Contributing guide](CONTRIBUTING.md): prerequisites, local verification, roadmap rules, documentation expectations, and commit guidance.
- [Project scope](docs/reference/project-scope.md): supported PKI domains, explicit non-goals, and current boundaries.
- [Target architecture](docs/reference/target-architecture.md): RA/API, policy, lifecycle, issuer adapter, key provider, audit, CRL, and OCSP boundaries.
- [State transitions](docs/reference/state-transitions.md): lifecycle status transitions and invalid transition boundaries.
- [API error codes](docs/reference/api-errors.md): public HTTP error mapping, ACME problem types, and audit error codes.
- [Observability reference](docs/reference/observability.md): structured logs, expvar counters, request IDs, and remaining observability gaps.
- [OpenAPI spec](docs/reference/openapi.json): lifecycle, operator, distribution, and ACME management API contract.
- [Compliance matrix](docs/reference/compliance-matrix.md): RFC 5280, RFC 6960, RFC 8555, CA/B Forum BR, Mozilla, and NIST coverage.
- [Improvement analysis alignment](docs/reference/improvement-analysis-alignment.md): mapping from uploaded improvement analyses to current evidence and future gaps.
- [PKI context](docs/architecture/pki-context.md): CA hierarchy, trust boundary, issuance, renewal, and revocation flow entry point.
- [Certificate profile policy](docs/policy/certificate-profiles.md): profile-as-code baseline and remaining profile gaps.
- [Algorithm policy](docs/policy/algorithm-policy.md): current crypto baseline, PQC stance, and algorithm-policy gaps.
- [CP/CPS map](docs/policy/cp-cps-map.md): evidence-oriented CP/CPS coverage map.
- [Threat model](docs/security/threat-model.md): main PKI assets, threats, current controls, and gaps.
- [Audit metadata reference](docs/reference/audit-metadata.md): audit metadata fields and stable result codes.
- [Audit log schema](docs/security/audit-log-schema.md): audit property, retention, tamper-evidence, and SIEM gap baseline.
- [Issuance consistency reference](docs/reference/issuance-consistency.md): signing claim, retry, and audit repair behavior.
- [Manual demo runbook](docs/runbooks/manual-demo.md): end-to-end local enrollment lifecycle demo.
- [Issuance runbook](docs/operations/issuance-runbook.md): normal and emergency issuance procedure.
- [Renewal runbook](docs/operations/renewal-runbook.md): renewal, failure handling, and deployment gap baseline.
- [Revocation runbook](docs/operations/revocation-runbook.md): revocation reasons and response procedure.
- [Mass revocation plan](docs/operations/mass-revocation-plan.md): mass incident drill steps and evidence.
- [Key ceremony](docs/operations/key-ceremony.md): key ceremony baseline and HSM/KMS gaps.
- [Backup and restore runbook](docs/operations/backup-restore-runbook.md): restore drill checklist tied to production recovery.
- [Production deployment guide](docs/runbooks/production-deployment.md): production architecture, secure sample config, startup checks, and rollback link.
- [Production recovery runbook](docs/runbooks/production-recovery.md): backup, rollback, restore, and DR drill rules.
- [Bootstrap API key runbook](docs/runbooks/bootstrap-api-key.md): first operator provisioning, bootstrap removal, key rotation, and disable flow.
- [Release process](docs/runbooks/release-process.md): release candidate checklist, verification, metadata, and approval gates.
- [Incident response runbook](docs/runbooks/incident-response.md): mis-issuance, key exposure, CA outage, renewal, revocation, and webhook incidents.
- [Webhook and outbox safety runbook](docs/runbooks/webhook-outbox-safety.md): receiver verification, replay cache, schema versioning, and dead-letter replay.
- [Public TLS readiness runbook](docs/runbooks/public-tls-readiness.md): validity ceilings, validation reuse, CAA checks, and mass-revocation drill.
- [ACME smoke harness](scripts/acme-smoke/README.md): local ACME client smoke harness; certbot remains default, but Windows non-admin certbot 5.6.0 exits before ACME traffic, so `-Client lego -LegoPath .tmp\lego-bin\lego.exe` is the HTTP-01 fallback.

Current imported-analysis execution batch: CSR and certificate correctness. The
repo keeps quickstart smoke commands, docs-as-code validation,
service route/OpenAPI parity, config/doc parity, public error mapping parity,
PostgreSQL parity coverage, and a high-confidence secret baseline scan in CI.
Next work is release operations and supply-chain evidence unless public TLS
issuance enables a linting hook.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

## Current Status

This is a lifecycle-service implementation in progress. Core lifecycle, profile policy, status publication, auth, audit, notifications, security/contribution docs, CI workflow, and ACME adapter foundations exist. A live lego HTTP-01 smoke reaches account, order, challenge validation, finalize, and certificate response against a harness-started local service. Current priority is release-candidate trust: API/doc/code parity, negative failure-mode tests, compatibility evidence, and certbot live coverage when a Linux or elevated Windows environment is available.
