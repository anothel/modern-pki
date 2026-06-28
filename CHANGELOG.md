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
- Issued-certificate DER golden coverage for SAN, KU, EKU, Basic Constraints,
  AIA, CRL Distribution Points, SKI, and AKI.
- Profile algorithm policy for CSR public key algorithm, minimum key size, and
  selected signing algorithm.

### Changed

- Roadmap is future-only; completed work belongs in reference docs, runbooks,
  or this changelog.

### Known Gaps

- Certbot live smoke remains environment-gated on Linux or elevated Windows.
- SBOM, release signing, SAST/SCA selection, full compatibility matrix, HSM/KMS
  provider boundary, tamper-evident audit storage, EAB, and DNS-01 remain
  future work.
