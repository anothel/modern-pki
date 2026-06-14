# modern-pki service

Go API service for the manual enrollment lifecycle MVP. It exposes HTTP endpoints for identities, certificate profiles, enrollments, certificate issuance, revocation, CRL publication, and audit events, backed by the SQL store and the `modern-pki-core` CLI for CSR inspection, certificate issuance, and CRL generation.

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

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `MODERN_PKI_ADDR` | `:8080` | HTTP listen address. |
| `MODERN_PKI_DB_DRIVER` | `sqlite` | Database driver name. Use `sqlite` locally or `pgx` for PostgreSQL. |
| `MODERN_PKI_DB_DSN` | `modern-pki.db` | Database DSN passed to `database/sql`. |
| `MODERN_PKI_CORE_BIN` | `modern-pki-core` | Path or command name for the core CLI. |

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
