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
- API key HMAC-SHA256 pepper support for new token hashes, with legacy SHA-256 fallback for existing keys.
- API key optional expiry enforcement and `last_used_at` tracking.
- API key rotation with one-time replacement tokens and token fingerprints.
- Production mode guard for `dev` auth and weak bootstrap API keys.
- Public `/healthz`, `/readyz`, and `/version` service endpoints.
- Audit metadata for request ID, client IP, actor, resource IDs, and failure codes.
- HTTP server operational timeouts and request body size limits.
- Lifecycle outbox messages.
- Webhook notification endpoints.
- Signed webhook delivery.
- Bounded outbox retry and dead-letter handling.
- Operator APIs for outbox listing and manual retry.
- Production webhook endpoint policy for HTTPS URLs and strong shared secrets.

### Project Governance And Verification

- `SECURITY.md` documents project security status, private reporting, supported version status, production expectations, secret handling, known constraints, and disclosure process.
- `CONTRIBUTING.md` documents project scope, prerequisites, local verification, roadmap rules, documentation expectations, agent Git ownership, and commit message guidance.
- GitHub Actions CI workflow exists for Go tests/build and CMake/CTest.

### ACME Protocol Adapter

- ACME directory and nonce endpoints.
- ACME nonce TTL, bounded in-memory retention, and expired nonce cleanup.
- JWS envelope parsing and one-time nonce replay protection.
- ES256/P-256, RS256/RSA, and EdDSA/Ed25519 JWS signature verification.
- Account key binding through EC/RSA/OKP JWK thumbprint and canonical JWK persistence.
- Existing account reuse by JWK thumbprint, contact update, account deactivation, and deactivated-account enforcement.
- Account ownership enforcement for new-order, challenge, finalize, and certificate download.
- ACME order, authorization, challenge, finalize, and certificate download flow.
- HTTP-01 challenge validation.
- Challenge `processing` state, retryable HTTP-01 validation failures, authorization polling, and `Retry-After`.
- HTTP-01 unsafe target blocking for localhost names, loopback, private, link-local, multicast, unspecified, metadata/link-local addresses, redirects, and dial-time DNS resolution.
- POST-as-GET for order, authorization, and certificate resources.
- ACME `Replay-Nonce`, directory `Link`, `Location`, and `application/problem+json` responses.
- `badNonce` problem type mapping.
- Malformed JWS and badNonce retry matrix coverage.
- Order and authorization expiration metadata and expired ready-order rejection.
- Certbot-shaped Go fixture for account, order, POST-as-GET, challenge, finalize, and certificate download.
- Live lego HTTP-01 smoke against a harness-started local service through account creation, order creation, authorization, challenge validation, finalize, and certificate response.
- ACME protocol compatibility fixes from live smoke: standard order `identifiers`, RFC8555 finalize `csr` payload support, HTTPS loopback proxy for local clients, and real smoke CA material for core issuance.
- ACME certificate download returns leaf PEM followed by issuer chain PEMs for GET and POST-as-GET.

## Current Next Big Work

### 1. Operational Safety Baseline

Goal: make local/demo defaults unable to leak into production by accident, and make service operation predictable before adding more feature surface.

Current status:

- HTTP server now uses explicit `http.Server` timeouts and max header size.
- HTTP API requests are capped at 1 MiB by default, with OCSP requests capped at 16 KiB.
- API key auth mode exists with operator, write, and read scopes.
- API key HMAC peppering exists for new/bootstrap/rotated keys, and production API key mode requires a strong pepper.
- API key create/list responses include optional expiry and last-used timestamps; expired Bearer tokens are rejected.
- API key rotation disables the old key and returns a one-time replacement token with a stable fingerprint.
- `MODERN_PKI_ENV=production` rejects `dev` auth and weak configured bootstrap API keys.
- Public `/healthz`, `/readyz`, and `/version` endpoints exist; readiness checks database reachability.
- ACME nonces expire after 10 minutes and are capped at 1024 in-memory entries.
- Default ACME HTTP-01 validation blocks unsafe network targets and unsafe redirect targets; local smoke override remains explicit opt-in config.
- Malformed ACME JWS requests and badNonce retry behavior are covered by protocol tests.
- Audit metadata includes request ID, client IP, actor, resource IDs, result codes, and error codes.
- Audit client IP metadata trusts `X-Forwarded-For` only from configured trusted proxies.
- Production mode enforces HTTPS URLs and strong shared secrets for new webhook notification endpoints.
- Storage enforces issuer-scoped certificate serial, CRL publication number, and ACME account key thumbprint uniqueness across SQL and memory stores.
- `SECURITY.md` and `CONTRIBUTING.md` exist at the repository root.
- GitHub Actions CI workflow exists for Go tests/build and CMake/CTest. This roadmap does not claim any remote CI run result.

External review triage from `modern-pki-analysis-and-roadmap.md`:

Nothing from the review is silently discarded. Each item is either implemented, accepted into this roadmap, or deferred with a reason.

| Review item | Decision | Reason | Roadmap slot |
| --- | --- | --- | --- |
| GitHub Actions CI for Go and CMake/CTest | Implemented | A local workflow exists under `.github/workflows/ci.yml`; remote run status is not claimed here. | Completed / Project Governance And Verification |
| Certbot real-client verification | Accepted | Lego already passes locally; certbot needs elevated Windows or non-Windows smoke to close the compatibility gap. | ACME Client Compatibility Hardening |
| Production guard for `dev` auth | Implemented | Demo auth must not be usable by accident in production mode. | Completed / Operator Operations |
| HTTP server timeouts and max header size | Implemented | Service operation should not depend on Go server zero-value timeout behavior. | Completed / Operator Operations |
| HTTP request body size limits | Implemented | JSON and OCSP handlers need bounded request bodies before broader exposure. | Completed / Operator Operations |
| ACME HTTP-01 SSRF defense | Implemented | Default HTTP-01 validation blocks unsafe hosts, redirects, and unsafe resolved IPs; explicit local smoke override remains opt-in. | Completed / ACME Protocol Adapter |
| ACME nonce TTL, cap, and cleanup | Implemented | One-time nonce replay protection exists; bounded retention is needed for long-running service operation. | Completed / ACME Protocol Adapter |
| API key expiry and `last_used_at` | Implemented | Adds bounded key lifetime and operator usage telemetry without changing token format. | Completed / Operator Operations |
| API key rotation and token fingerprint | Implemented | Lets operators replace exposed keys without manually creating and disabling two records. | Completed / Operator Operations |
| API key HMAC/pepper | Implemented | New token hashes use HMAC-SHA256 when `MODERN_PKI_API_KEY_PEPPER` is set; legacy SHA-256 rows remain readable for migration. | Completed / Operator Operations |
| `SECURITY.md` and `CONTRIBUTING.md` | Implemented | Operators and contributors now have a security policy and development path before broader usage. | Completed / Project Governance And Verification |
| `LICENSE` | Owner decision needed | License is a project/legal ownership choice, not a technical default. It should not be guessed by the agent. | Release readiness |
| Delegated OCSP responder required mode | Accepted later | Current fallback keeps local/dev issuance usable; strict production OCSP mode should be configurable. | Operations security follow-up |
| Richer audit fields | Partially accepted | Request ID/client IP/actor/resource/result/error are present; auth method, user agent, state transition, and approval reason remain useful. | Audit hardening follow-up |
| `/healthz`, `/readyz`, and `/version` | Implemented | Needed for deployment and smoke checks; readiness currently checks DB reachability. | Completed / Operator Operations |
| Code splitting for HTTP/API/lifecycle packages | Deferred | Useful only after behavior stabilizes; doing it now adds conflict risk without changing runtime capability. | Refactor after security and compatibility work |
| Versioned migrations, locks, checksum, and PostgreSQL tests | Accepted | Required for real upgrades and non-SQLite deployments, but after production safety gates. | Storage And Migration Hardening |
| Pagination, filters, and concurrency tests | Accepted | Needed before large inventories and concurrent operator traffic. | Storage And Migration Hardening |
| OpenAPI, runbooks, backup/restore, and operations docs | Accepted | Important for operators, but should follow the stabilized API and baseline deployment behavior. | Documentation hardening |
| DNS-01, EAB, UI, Kubernetes controller, PQC production path | Deferred | Useful capabilities, but they depend on the ACME, security, and operational baseline being solid first. | Not Next / later roadmap |

Next shape:

- Close issuance consistency first: recoverable/idempotent signing, DB uniqueness, and retry-safe finalization.
- Harden webhook delivery before adding more notification surface.
- Move ACME nonce handling toward multi-instance safety after the single-instance behavior stays green.
- Keep CI and local verification checks passing as changes land.

External code review triage from `modern-pki-code-level-review-2026-06-24.md`:

This review was code-level static analysis. Items already done are acknowledged, but roadmap slots focus on what still changes future work.

| Review item | Decision | Reason | Roadmap slot |
| --- | --- | --- | --- |
| Full clone/build/test/CI evidence | Accepted | CI config exists, but green remote CI, race, vet/staticcheck/gosec, and C++ sanitizer/fuzz evidence are separate release-readiness proof. | Verification hardening |
| Issuance happens before DB commit | Accepted P0 | A signed certificate can become orphaned if DB finalization fails; need idempotency, recoverable state, and serial uniqueness. | Issuance Consistency And Webhook Safety |
| Webhook default client timeout and SSRF defense | Accepted P0 | Timeout-free default client and weak endpoint network policy can stall workers or reach internal targets. | Issuance Consistency And Webhook Safety |
| ACME nonce is in-process memory | Accepted P0 | TTL/cap helps one instance only; multi-instance needs shared-store or signed stateless nonce design. | ACME Security Hardening |
| Production auth/config guard | Implemented | `dev` auth, weak bootstrap key, missing pepper, trusted proxy audit metadata, and webhook HTTPS/secret policy are guarded. | Completed / Operator Operations |
| Blind `X-Forwarded-For` trust | Implemented | Client IP audit now uses configured trusted proxies before accepting forwarded client IP metadata. | Completed / Operator Operations |
| Outbox lease, endpoint delivery state, retry jitter | Accepted | Current message-level processing can get stuck after worker death and can resend successful endpoints. | Outbox Delivery Hardening |
| DB uniqueness/index hardening | Implemented | Issuer serial, CRL publication number, ACME thumbprint, and cross-store parity now have storage enforcement/tests. | Completed / Operational Safety Baseline |
| OCSP lookup and response policy | Accepted | List-scan lookup and fixed `NextUpdate` are not enough for large inventories. | Status Publication Hardening |
| CSR/subject/SAN canonicalization | Accepted | Exact match is good baseline; IDNA, case, trailing dot, wildcard, and IP canonical forms need explicit policy/tests. | Issuance Policy Hardening |
| API pagination/filtering/sorting | Accepted | Large inventories need bounded list APIs and stable ordering. | Storage And Migration Hardening |
| Observability and rate-limit signals | Accepted | Operators need issuance, ACME, OCSP, webhook, auth, DB, and core CLI metrics before production claims. | Observability |
| Code splitting of large service/server/store files | Deferred | Useful after behavior stabilizes; refactor now would add churn without reducing immediate production risk. | Refactor after hardening |

### 2. ACME Client Compatibility Hardening

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

### 3. Issuance Consistency And Webhook Safety

- Make certificate issuance recoverable/idempotent when signing succeeds but DB finalization fails.
- Add tests for retrying finalization without creating a second certificate for one enrollment.
- Give webhook delivery a bounded default HTTP client timeout.
- Add webhook endpoint SSRF checks aligned with ACME HTTP-01 unsafe target blocking.

### 4. ACME Security Hardening

- ACME account key matrix across RSA, ECDSA P-256, and Ed25519 where clients expose variants.
- Certbot Linux/elevated smoke coverage.
- Keep lego smoke as the non-admin local regression check.
- Decide shared-store nonce vs signed stateless nonce for multi-instance deployments.
- Bind KID/account URL validation to the configured ACME base URL.

### 5. Outbox Delivery Hardening

- Add processing lease fields and lock expiry recovery.
- Track endpoint-level webhook delivery status.
- Add retry jitter.
- Keep message-level dead-letter APIs for operator recovery.

### 6. Storage And Migration Hardening

- Versioned migration table.
- Migration checksum and lock.
- PostgreSQL integration test.
- Pagination and filters for list APIs.
- Concurrency tests for serial allocation, CRL number allocation, ACME finalize, nonce replay, OCSP rotation, outbox retry, API key disable, and enrollment approval.
- Store contract tests for SQL and memory behavior parity.

### 7. Status Publication Hardening

- OCSP lookup by issuer and serial instead of scanning certificate lists.
- Configurable OCSP `NextUpdate` policy.
- OCSP response cache policy.
- Delegated responder strict production mode.

### 8. Issuance Policy Hardening

- DNS lowercase normalization.
- IDNA/punycode handling.
- Trailing dot policy.
- Wildcard depth and public suffix boundary checks.
- IPv4/IPv6 canonical SAN comparison.
- Explicit CSR signature verification tests.

### 9. Observability

- Issuance, revocation, renewal, CRL, OCSP, ACME, webhook, auth, DB, and core CLI metrics.
- API auth failure and rate-limit signals.
- Audit pagination and retention policy.

### 10. Certificate Rotation Automation

- Rotation schedules.
- Pre-expiry renewal windows.
- Key reuse vs key rollover policy.
- Evented rotation notifications.
- Safe cutover state tracking.

### 11. HSM And PKCS#11

- Issuer key reference model for HSM-backed keys.
- PKCS#11 signing boundary.
- Operator configuration for slots, labels, and PIN sources.
- Tests with a software token if available.

### 12. Crypto Agility

- Profile-level key algorithm and signature algorithm policy.
- RSA/ECDSA algorithm selection in issuance paths.
- Ed25519 feasibility check.
- Migration plan for algorithm deprecation.

### 13. Kubernetes Workload Identity

- Kubernetes service account identity mapping.
- Pod/workload certificate enrollment API.
- Optional Kubernetes CSR or projected token verification.
- Rotation workflow for workloads.

### 14. PQC And Hybrid Experiments

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
