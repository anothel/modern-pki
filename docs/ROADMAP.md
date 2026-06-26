# modern-pki roadmap

Only future work belongs here.

## P0: Production Safety

### Issuance Consistency

- Make certificate issuance recoverable when signing succeeds but DB finalization fails.
- Prevent duplicate signing work across multiple service nodes for the same enrollment.
- Add recovery or repair path for missing audit events after finalized issuance state is persisted.
- Define recovery behavior for signed material that cannot be persisted.

### Migration Hardening

- Add PostgreSQL migration/integration tests.
- Define rollback, backup, and restore rules around schema version and issuer key material.

### Webhook And Outbox Safety

- Decide and implement endpoint-level webhook delivery tracking if message-level status is not enough.
- Add webhook receiver runbook with timestamp skew, replay cache, and signature verification examples.
- Define webhook payload schema versioning.

### Readiness And Operations

- Add request ID format/length policy if external request IDs become operator-visible search keys.

## P1: ACME Security And Compatibility

### Real Client Coverage

- Run certbot smoke from Linux or elevated Windows.
- Run lego smoke as a local regression command.
- Convert certbot/lego differences into protocol fixture tests.
- Build compatibility matrix for client, OS, account key type, and smoke result.

### Multi-Node Nonce Safety

- Decide SQL-backed nonce store vs signed stateless nonce.
- Implement the chosen shared nonce strategy.
- Limit memory nonce behavior to local/single-node mode if shared nonce is added.
- Add replay tests that simulate multiple service nodes.

### HTTP-01 Egress Policy

- Harden DNS rebinding defenses.
- Validate resolver result and dialed address consistency.
- Make connect timeout, read timeout, redirect limit, and scheme policy explicit.
- Add tests for unsafe redirect targets.
- Add optional egress allow/deny list only if static safety rules prove insufficient.

### ACME Completeness

- Add account key coverage for RSA, ECDSA P-256, and Ed25519 where clients expose them.
- Bind KID/account URL validation to configured ACME base URL.
- Add account key rollover support.
- Add ACME revocation endpoint.
- Add rate limits for ACME account/order/challenge/finalize paths.
- Add RFC8555 conformance matrix.

## P2: Operator Surface

### Documentation And Release Readiness

- Get owner decision for `LICENSE`.
- Add README license status.
- Write production deployment guide with secure sample config.
- Write bootstrap API key provisioning/removal/rotation runbook.
- Write state transition reference.
- Write API error code reference.
- Write OpenAPI spec for lifecycle/operator APIs.
- Write release process.
- Write incident response runbook.
- Write backup/restore runbook.

### Observability And Audit

- Add structured logs.
- Add metrics for issuance, revocation, renewal, CRL, OCSP, ACME, webhook, auth, DB, and core CLI boundaries.
- Add auth failure metrics.
- Add rate-limit metrics.
- Add trace/span ID propagation where useful.
- Add audit fields: auth method, API key fingerprint, user agent, state transition, approval reason, and policy decision reason.
- Add audit pagination and retention policy.
- Add secret redaction tests for logs and audit records.

### API Scale

- Add pagination/filter/sort for identities.
- Add pagination/filter/sort for certificates.
- Add pagination/filter/sort for enrollments.
- Add pagination/filter/sort for audit events.
- Add pagination/filter/sort for outbox messages.
- Add indexes only for exposed query patterns.
- Add large inventory tests for stable ordering and response time.

## P3: Key Boundary And Core Robustness

### HSM And PKCS#11

- Define issuer/responder key reference model for HSM-backed keys.
- Separate file key provider from PKCS#11 signing provider.
- Document file provider as local/dev unless explicitly configured otherwise.
- Add audit tests proving key material is never recorded.
- Add PKCS#11 mock or software-token test path.

### Core CLI Contract

- Define JSON schema for Go-to-core CLI calls.
- Add contract tests for the Go/C++ boundary.
- Expose structured OpenSSL error details where useful for operator diagnosis.
- Add CSR parser fuzz target.
- Add OCSP parser fuzz target.
- Add CRL parser fuzz target.
- Document local fuzz commands.

## P4: Product Expansion

- Add certificate rotation automation.
- Add profile-level key algorithm policy.
- Add profile-level signature algorithm policy.
- Add crypto deprecation/migration plan.
- Add Kubernetes workload identity.
- Add DNS-01.
- Add External Account Binding.
- Add UI.
- Add PQC/hybrid experiments with clear non-production labeling.

## Defer Or Delete

- Defer large file splitting until repeated changes prove a stable boundary.
- Reject new abstractions until two real implementations exist or current code blocks a concrete requirement.
- Reject new dependencies unless stdlib/native code is materially worse.
- Reject new product surface while production safety, ACME compatibility, migration safety, and recovery docs remain incomplete.
