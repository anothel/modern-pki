# Changelog

All notable changes to this project will be recorded here.

This project is pre-1.0. Release candidates must record exact verification
commands and known gaps before tagging.

## Unreleased

### Added

- CI workflow for docs validation, service contract parity, secret baseline
  scan, Go service tests/build, PostgreSQL migration integration, and C++
  CMake/CTest.
- Apache-2.0 license file and docs-as-code validation.
- Release readiness, security, contribution, architecture, policy, operation,
  runbook, compliance, and ACME conformance documentation.
- Lifecycle service foundations for identity, issuer, certificate profile,
  enrollment, issuance, revocation, suspension, renewal, reissue, audit,
  outbox, webhook delivery, CRL, OCSP, and ACME adapter flows.

### Changed

- Roadmap is future-only; completed work belongs in reference docs, runbooks,
  or this changelog.

### Known Gaps

- PostgreSQL parity coverage still needs expansion for lifecycle, ACME nonce,
  outbox, audit, and migration behavior.
- Certbot live smoke remains environment-gated on Linux or elevated Windows.
- SBOM, release signing, SAST/SCA selection, full compatibility matrix, HSM/KMS
  provider boundary, tamper-evident audit storage, EAB, and DNS-01 remain
  future work.
