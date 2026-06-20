# modern-pki roadmap

This roadmap tracks the project as an operational PKI lifecycle service, not only a certificate generation tool.

## North Star

Build a service that can operate machine identity and certificate lifecycle infrastructure:

- identity and enrollment lifecycle
- profile-driven issuance policy
- renewal, reissue, revocation, suspension, expiration automation
- CRL and OCSP publication
- ACME automation
- operator audit and notification paths
- future machine identity, HSM/PKCS#11, and crypto agility work

## Completed

### Lifecycle MVP

- Manual identity, issuer, enrollment, approval, issuance, inventory, revocation, and audit flow.
- CSR inspection through the core CLI boundary.
- CSR SAN capture and policy requiring requested SANs to match CSR SANs.
- Certificate profile model with validity, subject, DNS/IP constraints, key usage, EKU, basic constraints, SKI, AKI, and SAN emission.
- Renewal and reissue flows.
- Suspend and resume certificate states.
- Expiration scan API and opt-in worker.

### Trust And Status

- CRL publication, latest issuer CRL endpoint, and CRL number tracking.
- OCSP request handling through core CLI.
- Delegated OCSP responder registration, validation, selection, disable, and rotate.
- Issuer chain and trust anchor export.

### Operator Operations

- API key auth mode with bootstrap operator key.
- API key scopes: operator, write, read.
- Audit metadata for request ID, client IP, actor, resource IDs, and failure codes.
- Lifecycle outbox messages.
- Webhook notification endpoints.
- Signed webhook delivery.
- Bounded outbox retry and dead-letter handling.
- Operator APIs for outbox listing and manual retry.

### ACME Protocol Adapter

- ACME directory and nonce endpoints.
- JWS envelope parsing and one-time nonce replay protection.
- ES256/P-256 JWS signature verification.
- Account key binding through JWK thumbprint and canonical JWK persistence.
- Account ownership enforcement for new-order, challenge, finalize, and certificate download.
- ACME order, authorization, challenge, finalize, and certificate download flow.
- HTTP-01 challenge validation.
- POST-as-GET for order, authorization, and certificate resources.
- ACME `Replay-Nonce`, directory `Link`, `Location`, and `application/problem+json` responses.
- `badNonce` problem type mapping.
- Order and authorization expiration metadata and expired ready-order rejection.
- Certbot-shaped Go fixture for account, order, POST-as-GET, challenge, finalize, and certificate download.

## Current Next Big Work

### 1. Live Certbot Smoke Harness

Goal: run a real ACME client against the local service and turn remaining compatibility gaps into tests.

Recommended shape:

- Start `modern-pki-service` with SQLite temp DB.
- Start a local HTTP-01 challenge responder controlled by the test harness.
- Run certbot or a certbot-compatible ACME client against `/acme/directory`.
- Capture exact request/response failures.
- Convert each failure into Go protocol fixture coverage before implementing fixes.

Expected output:

- `scripts/acme-smoke/` or `service/internal/httpapi` integration harness.
- Documented local command.
- Clear unsupported areas list after first real-client run.

Likely gaps:

- Certbot account creation payload shape.
- CSR/finalize payload format.
- Certificate chain response expectations.
- Problem document type mapping.
- Challenge retry and polling semantics.
- HTTP-01 responder host/port mapping in local dev.

## Prioritized Backlog

### 2. ACME Challenge Polling And Retry Semantics

- Add challenge validation retry behavior instead of one-shot invalidation.
- Add `processing` state if needed by client behavior.
- Add `Retry-After` for pending/processing resources.
- Map order-not-ready and authorization failure problem types.

### 3. ACME Account Management

- Account lookup by existing JWK thumbprint.
- Account update/deactivate endpoint.
- Contact update semantics.
- Better ACME problem responses for account conflicts and unauthorized key use.

### 4. ACME Key Algorithm Expansion

- RSA account keys.
- Ed25519 account keys if supported by selected clients.
- Keep ES256 as default fixture.

### 5. Machine Identity Enrollment

- First-class machine identity records for services, workloads, devices, and pods.
- Identity-bound issuance policy.
- Service/workload metadata and ownership.
- Audit views by machine identity.

### 6. Kubernetes Workload Identity

- Kubernetes service account identity mapping.
- Pod/workload certificate enrollment API.
- Optional Kubernetes CSR or projected token verification.
- Rotation workflow for workloads.

### 7. Certificate Rotation Automation

- Rotation schedules.
- Pre-expiry renewal windows.
- Key reuse vs key rollover policy.
- Evented rotation notifications.
- Safe cutover state tracking.

### 8. HSM And PKCS#11

- Issuer key reference model for HSM-backed keys.
- PKCS#11 signing boundary.
- Operator configuration for slots, labels, and PIN sources.
- Tests with a software token if available.

### 9. Crypto Agility

- Profile-level key algorithm and signature algorithm policy.
- RSA/ECDSA algorithm selection in issuance paths.
- Ed25519 feasibility check.
- Migration plan for algorithm deprecation.

### 10. PQC And Hybrid Experiments

- ML-DSA/ML-KEM research branch.
- Hybrid certificate experiment only after classical lifecycle is stable.
- Clear non-production labeling.

## Not Next

These are useful, but should wait until live ACME client smoke has been run:

- DNS-01 support.
- External account binding.
- UI.
- PQC production path.
- Kubernetes controller.

## Verification Policy

For each roadmap item:

- Add tests before implementation.
- Run targeted Go tests.
- Run `go test ./...`.
- Run `go build ./cmd/modern-pki-service`.
- Keep C++ smoke checks passing:
  - `ctest --test-dir build -C Debug -R modern_pki.core_ocsp --output-on-failure`
  - `ctest --test-dir build -C Debug -R modern_pki.core_cli_contract --output-on-failure`

