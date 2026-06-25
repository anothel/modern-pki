# modern-pki roadmap

This roadmap is for deciding what to build next, what to harden first, and what to defer. It is not a changelog.

## North Star

Build an operational PKI lifecycle service for machine identity:

- policy-bound identity, enrollment, approval, issuance, renewal, reissue, revocation, suspension, and expiration workflows
- CRL and OCSP publication that operators can trust under load
- ACME automation that works with real clients, not only internal fixtures
- audit, notification, recovery, and release practices that make production operation boring
- future HSM/PKCS#11, workload identity, and crypto agility without weakening the current baseline

## Current Direction

Prefer release and production safety over new feature surface.

Do next:

- make issuance, storage, migrations, webhook delivery, shutdown, and backup/restore failure modes explicit
- close ACME compatibility and multi-node safety gaps
- document operator workflows that must be stable before 1.0
- add tests where race, replay, idempotency, parsing, or data loss can occur

Do later:

- split large files only after behavior stabilizes
- add DNS-01, EAB, Kubernetes, UI, PQC, and larger product surface after production baseline is credible

## P0: Production Safety

These block any production-ready claim.

### Issuance Consistency

- Make certificate issuance recoverable/idempotent when signing succeeds but DB finalization fails.
- Add retry tests proving one enrollment cannot create duplicate certificates.
- Keep issuer-scoped serial, CRL number, and ACME account thumbprint uniqueness enforced in storage.

Acceptance:

- retrying a failed finalization returns or completes the same certificate record
- concurrent finalize/approval paths have regression coverage
- failed DB writes do not silently orphan issued material without recovery path

### Migration Hardening

- Add `schema_migrations` with version, checksum, applied timestamp, and dirty state.
- Add migration locking for concurrent startup.
- Add PostgreSQL integration coverage.
- Define backup/restore and rollback rules around schema version and issuer key material.

Acceptance:

- rerunning migrations is idempotent
- checksum mismatch fails startup loudly
- concurrent startup runs one migration path
- SQLite and PostgreSQL paths are covered

### Webhook And Outbox Safety

- Give webhook delivery a bounded HTTP client timeout.
- Add webhook endpoint SSRF/egress checks aligned with ACME HTTP-01 unsafe target blocking.
- Add processing leases and lock expiry recovery.
- Decide whether endpoint-level delivery status is needed before more webhook features.

Acceptance:

- worker death cannot permanently strand in-progress messages
- unsafe webhook targets are rejected
- retry/dead-letter behavior remains operator-visible

### Shutdown And Readiness

- Keep graceful shutdown covered for HTTP server and workers.
- Expand readiness beyond DB ping where useful: migration state, core CLI reachability, and key reference access.
- Keep request ID propagation covered, including server-generated IDs when callers omit `X-Request-ID`.

Acceptance:

- shutdown test covers in-flight request/worker cleanup
- readiness failures are actionable and do not expose secrets

## P1: ACME Security And Compatibility

### Real Client Coverage

- Run certbot smoke from Linux or elevated Windows.
- Keep lego smoke as the non-admin local regression check.
- Convert certbot/lego differences into protocol fixture tests.
- Build a compatibility matrix for client, OS, and account key type.

Acceptance:

- certbot account, order, challenge, finalize, and certificate download pass in at least one supported environment
- failures become reproducible tests or documented unsupported cases

### Multi-Node Nonce Safety

- Decide SQL-backed nonce store vs signed stateless nonce.
- Keep memory nonce store only for local/single-node mode if shared nonce is added.
- Add replay tests that simulate multiple nodes.

Acceptance:

- nonce issued by one node can be validated by another
- replay is rejected across nodes

### HTTP-01 Egress Policy

- Harden DNS rebinding defenses.
- Validate resolver result and dialed address consistency.
- Make connect/read timeout, redirect limit, and scheme policy explicit.
- Consider optional egress allow/deny lists only if the static safety rules are insufficient.

Acceptance:

- private, loopback, link-local, multicast, unspecified, and metadata targets stay blocked before and after redirects
- DNS rebinding and dial-time resolution behavior has tests

### ACME Completeness

- Add account key matrix coverage for RSA, ECDSA P-256, and Ed25519 where clients expose them.
- Bind KID/account URL validation to the configured ACME base URL.
- Track account key rollover, ACME revocation endpoint, rate limiting, and RFC8555 conformance matrix after current safety gaps.

## P2: Operator Surface

### Documentation And Release Readiness

- LICENSE owner decision and README license status.
- Production deployment guide with secure sample config.
- Bootstrap API key provisioning, removal, and rotation runbook.
- State transition and API error code references.
- OpenAPI spec for lifecycle/operator APIs.
- Webhook receiver guide with timestamp skew, replay cache, and signature verification examples.
- CHANGELOG and release process.
- Incident response and backup/restore runbooks.

Acceptance:

- a new operator can deploy a secure local/prod-like instance from docs
- public, protected, and ACME endpoints are clearly separated
- release notes can be produced without reading commit history

### Observability And Audit

- Add structured logs.
- Add metrics for issuance, revocation, renewal, CRL, OCSP, ACME, webhook, auth, DB, and core CLI boundaries.
- Add auth failure and rate-limit signals.
- Add trace/span ID propagation where it helps operations.
- Enrich audit with auth method, API key fingerprint, user agent, state transition, approval reason, and policy decision reason.
- Define audit pagination and retention.

Acceptance:

- common production failures have a metric/log/audit trail
- secrets are redacted in logs and audit records

### API Scale

- Add pagination/filter/sort for large list APIs.
- Prioritize identities, certificates, enrollments, audit events, and outbox messages.
- Add indexes only for query patterns the API actually exposes.

Acceptance:

- large inventory tests prove stable response time and ordering
- backwards compatibility behavior is documented

## P3: Key Boundary And Core Robustness

### HSM And PKCS#11

- Define issuer/responder key reference model for HSM-backed keys.
- Separate file key provider from PKCS#11 signing provider.
- Keep file provider documented as local/dev unless explicitly configured.
- Ensure audit never records key material.

Acceptance:

- signing API contract is clear
- PKCS#11 path has mock or software-token coverage before production claims

### Core CLI Contract

- Define JSON contract/schema for Go-to-core CLI calls.
- Expose structured OpenSSL error details where useful for operator diagnosis.
- Add CSR, OCSP, and CRL parser fuzz targets.

Acceptance:

- Go service and C++ core boundary can be tested without reading both implementations
- parser fuzzing has a documented local command

## P4: Product Expansion

Build only after P0/P1 are credible.

- certificate rotation automation
- profile-level key/signature algorithm policy and crypto agility
- Kubernetes workload identity
- DNS-01
- External Account Binding
- UI
- PQC or hybrid certificate experiments

## Defer Or Delete

Use this section to avoid turning every idea into work.

- Large file splitting: defer until behavior is stable or a change repeatedly touches one area and extraction reduces risk.
- New abstractions: defer until two real implementations exist or the current code blocks a concrete requirement.
- New dependencies: reject unless stdlib/native code is materially worse and the dependency reduces owned code.
- New product surface: reject while production safety, ACME compatibility, migration safety, and recovery docs remain incomplete.

## Verification Policy

For code changes:

- add or update the smallest useful regression test first for non-trivial logic
- run targeted Go tests
- run `go test ./...`
- run `go build ./cmd/modern-pki-service`
- keep C++ smoke checks passing when core behavior or service/core boundary changes:
  - `ctest --test-dir build -C Debug -R modern_pki.core_ocsp --output-on-failure`
  - `ctest --test-dir build -C Debug -R modern_pki.core_cli_contract --output-on-failure`

For docs-only roadmap changes:

- run `git diff --check`
- do not claim build/test status
