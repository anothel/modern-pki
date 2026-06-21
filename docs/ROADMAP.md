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
- Machine/service/workload/device identity metadata with owner, metadata JSON, and identity-bound DNS/IP SAN allow-lists.
- Identity SAN policy enforcement during enrollment, renewal/reissue enrollment creation, and final signing.
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
- ES256/P-256, RS256/RSA, and EdDSA/Ed25519 JWS signature verification.
- Account key binding through EC/RSA/OKP JWK thumbprint and canonical JWK persistence.
- Existing account reuse by JWK thumbprint, contact update, account deactivation, and deactivated-account enforcement.
- Account ownership enforcement for new-order, challenge, finalize, and certificate download.
- ACME order, authorization, challenge, finalize, and certificate download flow.
- HTTP-01 challenge validation.
- Challenge `processing` state, retryable HTTP-01 validation failures, authorization polling, and `Retry-After`.
- POST-as-GET for order, authorization, and certificate resources.
- ACME `Replay-Nonce`, directory `Link`, `Location`, and `application/problem+json` responses.
- `badNonce` problem type mapping.
- Order and authorization expiration metadata and expired ready-order rejection.
- Certbot-shaped Go fixture for account, order, POST-as-GET, challenge, finalize, and certificate download.
- Live lego HTTP-01 smoke against a harness-started local service through account creation, order creation, authorization, challenge validation, finalize, and certificate response.
- ACME protocol compatibility fixes from live smoke: standard order `identifiers`, RFC8555 finalize `csr` payload support, HTTPS loopback proxy for local clients, and real smoke CA material for core issuance.
- ACME certificate download returns leaf PEM followed by issuer chain PEMs for GET and POST-as-GET.

## Current Next Big Work

### 1. ACME Client Compatibility Hardening

Goal: make the ACME adapter boring under real clients, not only internal fixtures.

Current status:

- Harness scaffold added under `scripts/acme-smoke/`.
- Harness preflight now works without certbot or lego installed.
- Harness can optionally start `modern-pki-service` with temporary SQLite state by passing `-StartService`.
- Harness starts a temporary service binary instead of `go run`, using workspace-local Go caches.
- Harness defaults to certbot `webroot` mode and starts a local HTTP-01 static-file server.
- Runner behavior is covered by `scripts/acme-smoke/test-run-certbot-smoke.ps1`.
- Opt-in `MODERN_PKI_ACME_HTTP01_BASE_URL` support added for non-port-80 local HTTP-01 smoke.
- Certbot 5.6.0 was installed into a workspace-local Python virtualenv and invoked against the local service.
- Current certbot blocker: certbot on this Windows non-admin shell exits before ACME traffic with `certbot must be run on a shell with administrative rights`.
- Lego fallback is available via `-Client lego`; `-LegoPath` defaults to `lego`.
- Workspace-local lego `v4.35.2+dev-release` was installed at `.tmp\lego-bin\lego.exe`.
- Live lego HTTP-01 smoke passes from account creation to certificate response.

Next shape:

- Run certbot from an administrative Windows shell or non-Windows environment and convert any differences into protocol fixture coverage.
- Run certbot/lego account-key variants where clients expose them.
- Keep lego smoke as the non-admin local regression check.

Known-good lego command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -StartService -Run -DirectoryTimeoutSec 60
```

## Prioritized Backlog

### 2. Kubernetes Workload Identity

- Kubernetes service account identity mapping.
- Pod/workload certificate enrollment API.
- Optional Kubernetes CSR or projected token verification.
- Rotation workflow for workloads.

### 3. Certificate Rotation Automation

- Rotation schedules.
- Pre-expiry renewal windows.
- Key reuse vs key rollover policy.
- Evented rotation notifications.
- Safe cutover state tracking.

### 4. HSM And PKCS#11

- Issuer key reference model for HSM-backed keys.
- PKCS#11 signing boundary.
- Operator configuration for slots, labels, and PIN sources.
- Tests with a software token if available.

### 5. Crypto Agility

- Profile-level key algorithm and signature algorithm policy.
- RSA/ECDSA algorithm selection in issuance paths.
- Ed25519 feasibility check.
- Migration plan for algorithm deprecation.

### 6. PQC And Hybrid Experiments

- ML-DSA/ML-KEM research branch.
- Hybrid certificate experiment only after classical lifecycle is stable.
- Clear non-production labeling.

## Not Next

These are useful, but should wait until ACME HTTP-01 client compatibility is less brittle:

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
