# modern-pki service

Go API service for the manual enrollment lifecycle MVP. It exposes HTTP endpoints for identities, certificate profiles, enrollments, certificate issuance, revocation, CRL publication, OCSP response, and audit events, backed by the SQL store and the `modern-pki-core` CLI for CSR inspection, certificate issuance, CRL generation, and OCSP DER processing.

Enrollment creation inspects the CSR and stores CSR SANs separately from requested SANs. The current policy requires requested DNS/IP SANs to exactly match CSR DNS/IP SANs, ignoring order.

Identities support machine lifecycle metadata through `owner`, `metadata_json`, `allowed_dns_names`, and `allowed_ip_addresses`. When an identity allow-list is non-empty, enrollment, renewal/reissue enrollment creation, and final signing reject requested SANs outside that identity policy. Empty allow-lists preserve the existing unrestricted identity behavior.

The HTTP service applies operational request safety limits. The process uses explicit server timeouts and a 1 MiB default request body limit. OCSP requests are capped at 16 KiB.

Certificate profiles are first-class service records at:

- `POST /certificate-profiles`
- `GET /certificate-profiles`
- `GET /certificate-profiles/{id}`

Profiles currently model typed policy fields for validity, subject templates, allowed DNS/IP constraints, key usage, extended key usage, basic constraints, subject key identifiers, and authority key identifiers. Profile-driven X.509 extension emission is wired through the core CLI for basic constraints, key usage, extended key usage, subject key identifier, authority key identifier, and subject alternative name.

Profile policy is enforced when creating enrollments, creating renewal/reissue enrollments, and immediately before signing approved enrollments. Requested expiration cannot exceed `validity_period_seconds` from the current service clock. Requested DNS names must match allowed exact names or `*.example.test`-style suffix patterns when `allowed_dns_patterns` is set. Requested IP addresses must fall inside configured CIDR ranges when `allowed_ip_ranges` is set.

CRL publications are service-owned artifacts generated from certificate inventory and revocation records. The service selects revoked certificates for an issuer, assigns the next CRL number, calls the core CLI to build and sign the CRL, stores the PEM artifact, and publishes the latest issuer CRL over HTTP.

- `POST /crls`
- `GET /crls/{id}`
- `GET /issuers/{id}/crl`

Issuers can record parent issuer links, AIA URLs, CRL distribution points, and trust anchor status. Root CAs are trust anchors by default. Operator and clients can export issuer chains and active trust anchors:

- `GET /issuers/{id}/chain`
- `GET /trust/anchors`

ACME enrollment state is modeled as accounts, orders, authorizations, and challenges. Creating an order records requested DNS/IP identifiers and creates one pending authorization and challenge per identifier. Completing all challenges moves the order to `ready`. Finalizing a ready order creates an enrollment, approves it, issues the certificate, and marks the order `valid`.

- `POST /acme/accounts`
- `GET /acme/accounts`
- `POST /acme/orders`
- `GET /acme/orders/{id}`
- `GET /acme/orders/{id}/authorizations`
- `GET /acme/authorizations/{id}/challenges`
- `POST /acme/challenges/{id}/complete`
- `POST /acme/orders/{id}/finalize`

The service also exposes an ACME-shaped protocol adapter with directory discovery, nonce issuance, JWS envelope decoding, and one-time nonce replay protection:

- `GET /acme/directory`
- `HEAD /acme/new-nonce`
- `GET /acme/new-nonce`
- `POST /acme/new-account`
- `POST /acme/account/{id}`
- `POST /acme/new-order`
- `GET /acme/order/{id}`
- `POST /acme/order/{id}`
- `GET /acme/authz/{id}`
- `POST /acme/authz/{id}`
- `POST /acme/challenge/{id}`
- `POST /acme/order/{id}/finalize`
- `GET /acme/cert/{id}`
- `POST /acme/cert/{id}`

Protocol adapter requests use `Content-Type: application/jose+json` and JSON JWS fields `protected`, `payload`, and `signature`. The protected header must include `alg: ES256`, `RS256`, or `EdDSA`, a fresh `nonce` from `/acme/new-nonce`, and the exact request `url`. ACME nonces are single-use, expire after 10 minutes, and are retained in a bounded in-memory cache of 1024 entries. New-account requests bind the account to the submitted P-256, RSA, or OKP/Ed25519 JWK thumbprint and canonical JWK; repeated new-account requests with the same account key return the existing account. Later `kid`-based requests verify the JWS signature against the stored account key and reject mismatched account IDs or invalid signatures. Account POST requests update contacts or deactivate the account. Deactivated accounts cannot create orders or access order, authorization, challenge, finalize, or certificate resources. ACME POST responses include a fresh `Replay-Nonce` and directory `Link`; protocol errors use `application/problem+json` with malformed JWS and badNonce retry coverage. Orders and authorizations expose `identifiers` and `expires`, and expired ready orders are rejected and marked invalid. POST-as-GET is supported for order, authorization, and certificate resources. HTTP-01 challenge validation fetches `http://{identifier}/.well-known/acme-challenge/{token}` and expects `{token}.{account_key_thumbprint}`. Default HTTP-01 validation rejects unsafe targets before fetch and redirect follow, including localhost names, loopback, private, link-local, multicast, unspecified, and metadata/link-local addresses; DNS resolution is also checked in the dial path. Challenge validation failures keep the authorization and order pending, move the challenge to `processing`, and return `Retry-After` so clients can poll the authorization until validation succeeds. Finalize accepts the standard RFC8555 `csr` base64url DER payload and the internal `csr_pem` compatibility payload. Finalized orders expose `GET` and POST-as-GET `/acme/cert/{id}` for `application/pem-certificate-chain` download with the issued leaf followed by issuer chain PEMs. The adapter has passed a local live lego HTTP-01 smoke. Remaining compatibility gaps include certbot live coverage from an elevated/non-Windows shell, external account binding, and DNS-01.

For local ACME smoke tests, `MODERN_PKI_ACME_HTTP01_BASE_URL` can override the HTTP-01 fetch base URL. It is empty by default. When set, the verifier ignores the requested identifier host and fetches `/.well-known/acme-challenge/{token}` from the configured base URL. This override is trusted operator configuration and can target loopback for local smoke runs; keep it disabled around real infrastructure. `MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS` is also available for the smoke harness; it creates a local machine identity, issuer, certificate profile, and temporary CA key material. Keep it disabled outside local smoke runs. See the root [security policy](../SECURITY.md) before using smoke-only settings around real infrastructure.

Certificate lifecycle operations include revocation, suspension, and resumption:

- `POST /certificates/{id}/revoke`
- `POST /certificates/{id}/suspend`
- `POST /certificates/{id}/resume`
- `POST /certificates/{id}/renew`
- `POST /certificates/{id}/reissue`
- `POST /certificates/expiration-scan`

Normal revocation accepts only `valid` certificates. Forced revocation accepts `valid` and `suspended` certificates by posting `{"force": true}` with the revocation reason.
Renewal creates a new pending enrollment from a valid certificate, copying identity, issuer, profile, subject, and SANs while accepting a new CSR and requested expiration.
Reissue creates a new pending enrollment from a valid certificate with a new CSR while preserving the original certificate expiration.
Expiration scans mark `valid` and `suspended` certificates as `expired` when `not_after` is in the past. They emit one renewal warning for each `valid` certificate inside the requested warning window, tracked by `renewal_notified_at`.
The expiration scan worker is disabled by default. Set `MODERN_PKI_EXPIRATION_SCAN_ENABLED=true` to run scans automatically on startup and then at the configured interval.

Notification endpoints deliver lifecycle outbox events to operator webhooks:

- `POST /notification-endpoints`
- `GET /notification-endpoints`
- `POST /notification-endpoints/{id}/disable`

Webhook endpoints require a shared secret when created. Deliveries receive JSON with `outbox_message_id`, `event_type`, `payload`, and `created_at`. Empty `event_types` subscribes to all lifecycle outbox event types. Delivery requests include `X-Modern-PKI-Event`, `X-Modern-PKI-Delivery`, `X-Modern-PKI-Timestamp`, and `X-Modern-PKI-Signature`. The signature is `sha256=<hex HMAC-SHA256(secret, timestamp + "." + raw_body)>`; receivers should reject stale timestamps to reduce replay risk. Failed webhook delivery creates a failed job attempt and reschedules the outbox message for retry after one minute.

Outbox operations expose delivery state for operators:

- `GET /outbox/messages`
- `GET /outbox/messages?status=dead_letter`
- `POST /outbox/messages/{id}/retry`

Webhook delivery uses bounded retry with capped backoff: 1 minute, 5 minutes, 15 minutes, then 1 hour. Messages move to `dead_letter` after the configured max attempts. Manual retry resets a failed or dead-letter message to `pending`.

OCSP responders can be registered with `POST /issuers/{id}/ocsp-responders`, listed with `GET /issuers/{id}/ocsp-responders`, disabled with `POST /issuers/{id}/ocsp-responders/{responderID}/disable`, and atomically rotated with `POST /issuers/{id}/ocsp-responders/rotate`.

OCSP response is available at `POST /ocsp`. Requests must use `Content-Type: application/ocsp-request`; successful responses use `Content-Type: application/ocsp-response`. The service selects the responder issuer from the OCSP CertID hash algorithm plus issuer name/key hash, maps requested serials to `good`, `revoked`, or `unknown` from certificate inventory and revocation records, preserves OCSP nonce extensions in signed responses, and delegates OCSP response signing to the core CLI.

Only one active OCSP responder is allowed per issuer. Registering a replacement requires disabling the current active responder first, or using rotate to disable the current active responder and create the replacement in one transaction. Rotate fails with a lifecycle conflict when no active responder exists.

When a matched issuer has an active responder, `POST /ocsp` signs with that responder certificate and key reference. When no active responder exists, the service falls back to issuer direct signing for compatibility.

Responder certificates are validated by the core CLI before storage and must be issued by the issuer, be non-CA certificates, and carry the OCSP Signing EKU.

Audit events include structured `metadata_json` for lifecycle resource IDs and successful result codes. HTTP requests can attach `X-Request-ID`; the service records it with the client IP for mutating operations.

API authentication defaults to `dev` mode for local compatibility. In `dev` mode, the service uses `X-Actor` as the audit actor and allows requests without credentials. Set `MODERN_PKI_AUTH_MODE=api_key` to require `Authorization: Bearer <token>` for lifecycle and operator APIs. `POST /ocsp`, `GET /crls/{id}`, and `GET /issuers/{id}/crl` remain public distribution endpoints. Bootstrap an initial operator key by setting `MODERN_PKI_BOOTSTRAP_API_KEY`; the service stores only a SHA-256 token hash.

Set `MODERN_PKI_ENV=production` for production startup checks. Production mode rejects `dev` auth mode and rejects configured bootstrap API keys shorter than 32 characters or matching common defaults such as `change-me`.

Operational probes are public:

- `GET /healthz` returns process liveness.
- `GET /readyz` checks database reachability.
- `GET /version` returns service build metadata.

API keys are managed by operator-scoped keys:

- `POST /api-keys`
- `GET /api-keys`
- `POST /api-keys/{id}/disable`

Scopes are ordered as `operator`, `write`, and `read`. `operator` can access all protected APIs, including API key management, outbox operations, audit events, and expiration scans. `write` can read and mutate lifecycle resources. `read` can only read non-operator APIs. Created API keys return the generated token once in the creation response. List and disable responses never include token material.

Example:

```powershell
$env:MODERN_PKI_AUTH_MODE = "api_key"
$env:MODERN_PKI_BOOTSTRAP_API_KEY = "change-me"
$env:MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR = "ops-admin"
go run ./cmd/modern-pki-service

curl.exe -H "Authorization: Bearer change-me" http://localhost:8080/identities

curl.exe -X POST http://localhost:8080/api-keys `
  -H "Authorization: Bearer change-me" `
  -H "Content-Type: application/json" `
  -d '{"name":"reader","actor":"read-client","scopes":["read"]}'
```

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `MODERN_PKI_ADDR` | `:8080` | HTTP listen address. |
| `MODERN_PKI_DB_DRIVER` | `sqlite` | Database driver name. Use `sqlite` locally or `pgx` for PostgreSQL. |
| `MODERN_PKI_DB_DSN` | `modern-pki.db` | Database DSN passed to `database/sql`. |
| `MODERN_PKI_CORE_BIN` | `modern-pki-core` | Path or command name for the core CLI. |
| `MODERN_PKI_ENV` | empty | Set to `production` to enable production startup checks. |
| `MODERN_PKI_AUTH_MODE` | `dev` | Auth mode. Use `dev` for local `X-Actor`; use `api_key` for Bearer token auth. |
| `MODERN_PKI_BOOTSTRAP_API_KEY` | empty | Optional initial API key token. Stored as a SHA-256 hash. In production, configured bootstrap tokens must be at least 32 characters and not common defaults. |
| `MODERN_PKI_BOOTSTRAP_API_KEY_NAME` | `bootstrap` | Name stored for the bootstrap API key. |
| `MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR` | `bootstrap` | Audit actor assigned to the bootstrap API key. |
| `MODERN_PKI_OUTBOX_ENABLED` | `true` | Enables lifecycle outbox dispatch worker. |
| `MODERN_PKI_OUTBOX_INTERVAL` | `5s` | Outbox dispatch worker interval. |
| `MODERN_PKI_OUTBOX_BATCH_SIZE` | `10` | Max outbox messages dispatched per worker run. |
| `MODERN_PKI_EXPIRATION_SCAN_ENABLED` | `false` | Enables automatic certificate expiration scans. |
| `MODERN_PKI_EXPIRATION_SCAN_INTERVAL` | `1h` | Expiration scan worker interval. |
| `MODERN_PKI_EXPIRATION_WARNING_WINDOW` | `720h` | Renewal warning window for valid certificates. |
| `MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE` | `100` | Max certificates processed per expiration scan. |
| `MODERN_PKI_ACME_HTTP01_BASE_URL` | empty | Optional local smoke override for HTTP-01 challenge fetches. |
| `MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS` | `false` | Local smoke-only bootstrap for default ACME identity, issuer, and profile. |
| `MODERN_PKI_ACME_DEFAULT_VALIDITY` | `24h` | Validity used by ACME smoke defaults. |
| `MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF` | `.tmp/acme-smoke/acme-smoke-issuer.key` | Local smoke CA private key path used only when ACME defaults bootstrap is enabled. |

Initial schema migration runs on startup before the HTTP server starts. SQLite uses `internal/store/migrations/0001_init_sqlite.sql`; `pgx` uses `internal/store/migrations/0001_init.sql`.

## Manual Verification

Repository owner runs tests and builds. Suggested commands:

```powershell
cd service
go test ./...
go build ./cmd/modern-pki-service
$env:MODERN_PKI_ADDR = ":8080"
$env:MODERN_PKI_DB_DRIVER = "sqlite"
$env:MODERN_PKI_DB_DSN = "modern-pki.db"
go run ./cmd/modern-pki-service
```
