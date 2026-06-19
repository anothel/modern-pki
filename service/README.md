# modern-pki service

Go API service for the manual enrollment lifecycle MVP. It exposes HTTP endpoints for identities, certificate profiles, enrollments, certificate issuance, revocation, CRL publication, OCSP response, and audit events, backed by the SQL store and the `modern-pki-core` CLI for CSR inspection, certificate issuance, CRL generation, and OCSP DER processing.

Enrollment creation inspects the CSR and stores CSR SANs separately from requested SANs. The current policy requires requested DNS/IP SANs to exactly match CSR DNS/IP SANs, ignoring order.

Certificate profiles are first-class service records at:

- `POST /certificate-profiles`
- `GET /certificate-profiles`
- `GET /certificate-profiles/{id}`

Profiles currently model typed policy fields for validity, subject templates, allowed DNS/IP constraints, key usage, extended key usage, basic constraints, subject key identifiers, and authority key identifiers. Profile-driven X.509 extension emission is wired through the core CLI for basic constraints, key usage, extended key usage, subject key identifier, authority key identifier, and subject alternative name.

CRL publications are service-owned artifacts generated from certificate inventory and revocation records. The service selects revoked certificates for an issuer, assigns the next CRL number, calls the core CLI to build and sign the CRL, stores the PEM artifact, and publishes the latest issuer CRL over HTTP.

- `POST /crls`
- `GET /crls/{id}`
- `GET /issuers/{id}/crl`

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

API authentication defaults to `dev` mode for local compatibility. In `dev` mode, the service uses `X-Actor` as the audit actor and allows requests without credentials. Set `MODERN_PKI_AUTH_MODE=api_key` to require `Authorization: Bearer <token>` for lifecycle and operator APIs. `POST /ocsp`, `GET /crls/{id}`, and `GET /issuers/{id}/crl` remain public distribution endpoints. Bootstrap an initial key by setting `MODERN_PKI_BOOTSTRAP_API_KEY`; the service stores only a SHA-256 token hash.

Example:

```powershell
$env:MODERN_PKI_AUTH_MODE = "api_key"
$env:MODERN_PKI_BOOTSTRAP_API_KEY = "change-me"
$env:MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR = "ops-admin"
go run ./cmd/modern-pki-service

curl.exe -H "Authorization: Bearer change-me" http://localhost:8080/identities
```

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `MODERN_PKI_ADDR` | `:8080` | HTTP listen address. |
| `MODERN_PKI_DB_DRIVER` | `sqlite` | Database driver name. Use `sqlite` locally or `pgx` for PostgreSQL. |
| `MODERN_PKI_DB_DSN` | `modern-pki.db` | Database DSN passed to `database/sql`. |
| `MODERN_PKI_CORE_BIN` | `modern-pki-core` | Path or command name for the core CLI. |
| `MODERN_PKI_AUTH_MODE` | `dev` | Auth mode. Use `dev` for local `X-Actor`; use `api_key` for Bearer token auth. |
| `MODERN_PKI_BOOTSTRAP_API_KEY` | empty | Optional initial API key token. Stored as a SHA-256 hash. |
| `MODERN_PKI_BOOTSTRAP_API_KEY_NAME` | `bootstrap` | Name stored for the bootstrap API key. |
| `MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR` | `bootstrap` | Audit actor assigned to the bootstrap API key. |
| `MODERN_PKI_OUTBOX_ENABLED` | `true` | Enables lifecycle outbox dispatch worker. |
| `MODERN_PKI_OUTBOX_INTERVAL` | `5s` | Outbox dispatch worker interval. |
| `MODERN_PKI_OUTBOX_BATCH_SIZE` | `10` | Max outbox messages dispatched per worker run. |
| `MODERN_PKI_EXPIRATION_SCAN_ENABLED` | `false` | Enables automatic certificate expiration scans. |
| `MODERN_PKI_EXPIRATION_SCAN_INTERVAL` | `1h` | Expiration scan worker interval. |
| `MODERN_PKI_EXPIRATION_WARNING_WINDOW` | `720h` | Renewal warning window for valid certificates. |
| `MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE` | `100` | Max certificates processed per expiration scan. |

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
