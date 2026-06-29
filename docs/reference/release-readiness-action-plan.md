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
| Service contract parity | `scripts/validate-service-contracts.py` checks route/OpenAPI parity, config/env docs parity, and public error mapping docs parity; `scripts/validate-core-cli-contracts.py` checks Go-to-core CLI JSON field parity against the contract reference, including structured OpenSSL diagnostic details on core CLI failures; env-gated core boundary integration tests run the Go runner against the real C++ CLI. |
| Secret baseline | `scripts/security-baseline-scan.py` checks high-confidence committed secret patterns. |
| Release trust | README quickstart smoke checklist, `CHANGELOG.md`, CI run/badge strategy in the release process, release evidence manifest validation, and tagged release artifact workflow. |
| Core robustness | Optional local libFuzzer targets cover CSR PEM inspection, OCSP request DER inspection, and CRL DER inspection. |
| Issuance failure-mode coverage | Lifecycle tests cover duplicate issuer serial rejection without issuing the second enrollment; memory, SQLite, and PostgreSQL parity tests cover duplicate certificate finalization keys, stale issuance-attempt updates, outbox, audit, migration, and ACME nonce behavior. |
| Certificate correctness | Core issue profile tests parse issued DER and assert SAN, KU, EKU, Basic Constraints, AIA, CRL Distribution Points, SKI, and AKI; core CSR fixtures include real weak-key metadata coverage; profile policy enforces CSR key algorithm/size, selected signing algorithm, invalid KU/EKU combinations, forbidden CSR-requested extensions, SAN presence, wildcard policy, IP SAN policy, and oversized SAN rejection; core issuance rejects expired or not-yet-valid issuer certificates and DNS SANs outside issuer DNS name constraints before signing. |
| CI shape | Workflow includes docs validation, release evidence validation, secret baseline, Go tests/vet/govulncheck/build, PostgreSQL integration, C++ CMake, and CTest. |
| Lifecycle scope | Identity, issuer, profile, enrollment, approval, issuance, renewal, reissue, revocation, suspension, CRL, OCSP, audit, outbox, webhook, and ACME foundations exist. |
| Public TLS guardrails | Validity ceilings, validation evidence age, CAA DNSSEC/RFC 8657 policy, and mass-revocation planning docs exist. |
| ACME baseline | lego HTTP-01 smoke evidence exists; certbot remains environment-gated. |

## Execution Order

### Batch 1: Certificate Correctness

Harden CSR and issued-certificate policy:

- Public TLS lint hook only where public issuance is enabled.

Exit criteria:

- Approval and signing reject known bad CSRs and profiles.
- CSR and algorithm policy reject known bad requests before signing.

### Batch 2: Release And Supply Chain

Make release artifacts auditable:

- Compatibility matrix evidence for client, OS, Go, OpenSSL,
  SQLite/PostgreSQL, and smoke result.

Exit criteria:

- A release candidate includes provenance, dependency, compatibility, and
  security-scan evidence.

### Batch 3: Operations And Key Boundary

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
| Build a trustworthy release candidate first. | README quickstart smoke checklist, CHANGELOG, CI workflow shape, and release-process evidence strategy exist. |
| Automate API/docs/code parity. | Route/OpenAPI, config/doc, error-envelope, and Go-to-core CLI JSON contract parity checks. |
| Add Go/C++ boundary contract tests. | Fake-command Go runner tests, C++ CLI contract tests, JSON contract drift validation, and env-gated real CLI integration tests exist. |
| Strengthen ACME compatibility. | Certbot smoke plus fixture conversion and compatibility matrix. |
| Strengthen CSR/certificate correctness. | DER golden tests, profile algorithm policy, invalid KU/EKU checks, real weak-key CSR metadata coverage, CSR linting for forbidden extensions and SAN policy cases, and issuer validity/name-constraint negative fixtures exist; remaining work is public TLS lint integration only if public issuance is enabled. |
| Strengthen issuance consistency tests. | Signer/DB failure, lease race, serial collision, and PostgreSQL parity coverage exist. |
| Add parser fuzzing. | Optional local libFuzzer targets and commands exist for CSR, OCSP, and CRL parser boundaries. |
| Strengthen webhook/outbox safety tests. | Receiver replay/signature, timeout, unsafe redirect/egress, retry, and dead-letter coverage exist. |
| Add audit tamper-evidence. | P2 Audit, Access, And Operations. |
| Add HSM/KMS/PKCS#11 boundary. | P2 Key Boundary. |
| Add SBOM/release signing/SAST/SCA. | Release evidence selects syft, cosign, go vet, and govulncheck; tagged release workflow builds archives, checksums, SBOM, and cosign signatures. |
| Do not refactor large files prematurely. | P3 split gates require behavior coverage and stable boundaries. |
