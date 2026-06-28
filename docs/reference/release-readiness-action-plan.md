# Release Readiness Action Plan

This file turns the uploaded 2026-06-28 repository analysis into a project
execution plan. It keeps [ROADMAP](../ROADMAP.md) future-only and prevents
analysis findings from becoming scattered TODO lists.

## Current Thesis

`modern-pki` should not expand feature surface first. The next major work is to
make the existing lifecycle service trustworthy as a pre-1.0 security utility:
verified builds, route/API/doc parity, negative tests, compatibility evidence,
and release-repeatable operations.

## Evidence Already Present

| Area | Current evidence |
| --- | --- |
| Baseline docs | README, SECURITY, CONTRIBUTING, roadmap, OpenAPI, runbooks, threat model, architecture, policy, ADR, and alignment docs. |
| Docs-as-code | `scripts/validate-docs.py` checks required docs, README links, OpenAPI JSON, and license state. |
| Service contract parity | `scripts/validate-service-contracts.py` checks route/OpenAPI parity, config/env docs parity, and public error mapping docs parity. |
| Secret baseline | `scripts/security-baseline-scan.py` checks high-confidence committed secret patterns. |
| Store failure-mode parity | Memory and SQLite tests cover duplicate certificate finalization keys and stale issuance-attempt finalization updates. |
| CI shape | Workflow includes docs validation, secret baseline, Go tests/build, PostgreSQL integration, C++ CMake, and CTest. |
| Lifecycle scope | Identity, issuer, profile, enrollment, approval, issuance, renewal, reissue, revocation, suspension, CRL, OCSP, audit, outbox, webhook, and ACME foundations exist. |
| Public TLS guardrails | Validity ceilings, validation evidence age, CAA DNSSEC/RFC 8657 policy, and mass-revocation planning docs exist. |
| ACME baseline | lego HTTP-01 smoke evidence exists; certbot remains environment-gated. |

## Execution Order

### Batch 1: Release Trust

Close these before adding new operator/product surface:

- Add README quickstart command smoke check or deterministic manual checklist.
- Add CHANGELOG.

Exit criteria:

- CI and local verification commands are known and documented.
- OpenAPI, service docs, and error docs fail CI when they drift from code.
- A release candidate can be reviewed from recorded command output, not trust.

### Batch 2: PKI Failure Modes

Close the highest-risk PKI correctness paths:

- Signer success plus DB finalization failure recovery.
- Issuance attempt lease races.
- Lifecycle-level serial collision and duplicate serial rejection.
- ACME nonce/JWS/account replay and mismatch cases.
- Webhook invalid HMAC, replay, timeout, unsafe redirect/egress, retry, and
  dead-letter replay.
- PostgreSQL parity for lifecycle, outbox, audit, nonce, and migration behavior
  where memory/SQLite parity already exists.

Exit criteria:

- Tests cover the failure modes most likely to create mis-issuance, duplicate
  signing, replay, or untraceable state.

### Batch 3: Certificate Correctness

Harden CSR and issued-certificate policy:

- CSR linting for key, SAN/CN, forbidden extension, malformed PEM, wildcard, IP
  SAN, and oversized SAN policy.
- Profile-level key and signature algorithm policy.
- DER golden tests for X.509 extensions.
- Public TLS lint hook only where public issuance is enabled.

Exit criteria:

- Approval and signing reject known bad CSRs and profiles.
- Issued DER is parsed and asserted, not trusted by request shape alone.

### Batch 4: Release And Supply Chain

Make release artifacts auditable:

- SBOM decision and implementation.
- Release artifact signing decision and implementation.
- SAST/SCA tool choice and CI wiring.
- Compatibility matrix for client, OS, Go, OpenSSL, SQLite/PostgreSQL, and
  smoke result.

Exit criteria:

- A release candidate includes provenance, dependency, compatibility, and
  security-scan evidence.

### Batch 5: Operations And Key Boundary

Raise production-operating confidence:

- HSM/KMS/PKCS#11 semantics and file-provider split.
- Non-exportable-key API and audit behavior.
- Key ceremony and intermediate rollover drill evidence.
- Tamper-evident audit design and SIEM export examples.
- RBAC/ABAC and break-glass model.
- Synthetic CRL/OCSP/ACME/deployment health checks after a deploy target exists.

Exit criteria:

- Production signing keys, audit records, operator roles, and recovery drills
  have explicit evidence paths.

## Deferred Unless Triggered

| Item | Trigger |
| --- | --- |
| EAB | Real subscriber/account integration requires it. |
| DNS-01 | Operator-owned DNS provider is selected. |
| Broad discovery scanners | One concrete import source proves inventory and ownership fields. |
| UI | Operator APIs, filters, pagination, and workflows stabilize. |
| Kubernetes/deploy adapters | First deployment target is chosen. |
| PQC/hybrid production | Dependencies and relying-party support are real; lab-only until then. |
| Large file split | Tests cover behavior and repeated changes prove a stable boundary. |

## Mapping From 2026-06-28 Analysis

| Analysis recommendation | Project action |
| --- | --- |
| Build a trustworthy release candidate first. | P0 Release Trust and this action plan Batch 1. |
| Automate API/docs/code parity. | Route/OpenAPI, config/doc, error-envelope parity checks. |
| Strengthen ACME compatibility. | Certbot smoke plus fixture conversion and compatibility matrix. |
| Strengthen CSR/certificate correctness. | CSR linting, profile algorithm policy, DER golden tests. |
| Strengthen issuance consistency tests. | Signer/DB failure, lease race, serial collision coverage. |
| Strengthen webhook/outbox safety tests. | Replay, signature, timeout, egress, retry, dead-letter coverage. |
| Add audit tamper-evidence. | P2 Audit, Access, And Operations. |
| Add HSM/KMS/PKCS#11 boundary. | P2 Key Boundary. |
| Add SBOM/release signing/SAST/SCA. | P1 Release Operations. |
| Do not refactor large files prematurely. | P3 split gates require behavior coverage and stable boundaries. |
