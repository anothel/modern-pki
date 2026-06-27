# Production Deployment Guide

This guide is the minimum production shape for `modern-pki`. It assumes a
trusted operator controls the database, key provider, reverse proxy, and backup
system.

## Required Architecture

- Run the Go service behind a TLS-terminating reverse proxy or private service
  mesh.
- Use PostgreSQL for shared production state.
- Keep issuer and OCSP responder private keys outside the database. Store only
  `key_ref` values in `modern-pki`.
- Run every service node with the same database, API key pepper, ACME base URL
  behavior, public TLS CAA settings, and key-provider access.
- Use SQL ACME nonce storage for multi-node deployments.
- Back up the database and key-provider metadata before migrations and issuer,
  responder, CRL, or lifecycle-job bulk changes.

## Secure Sample Environment

Use placeholders only. Do not commit real values.

```powershell
$env:MODERN_PKI_ENV = "production"
$env:MODERN_PKI_ADDR = ":8080"

$env:MODERN_PKI_DB_DRIVER = "pgx"
$env:MODERN_PKI_DB_DSN = "postgres://modern_pki:<password>@db.example.internal:5432/modern_pki?sslmode=require"

$env:MODERN_PKI_CORE_BIN = "C:\modern-pki\bin\modern-pki-core.exe"

$env:MODERN_PKI_AUTH_MODE = "api_key"
$env:MODERN_PKI_API_KEY_PEPPER = "<32+ chars random secret from secret manager>"

$env:MODERN_PKI_ACME_NONCE_STORE = "sql"
$env:MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS = "false"
$env:MODERN_PKI_ACME_HTTP01_BASE_URL = ""

$env:MODERN_PKI_OUTBOX_ENABLED = "true"
$env:MODERN_PKI_OUTBOX_INTERVAL = "5s"
$env:MODERN_PKI_OUTBOX_BATCH_SIZE = "10"

$env:MODERN_PKI_EXPIRATION_SCAN_ENABLED = "true"
$env:MODERN_PKI_EXPIRATION_SCAN_INTERVAL = "1h"
$env:MODERN_PKI_EXPIRATION_WARNING_WINDOW = "720h"
$env:MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE = "100"

$env:MODERN_PKI_PUBLIC_TLS_CAA_ISSUER_DOMAIN = "ca.example"
$env:MODERN_PKI_PUBLIC_TLS_CAA_ACCOUNT_URI = "https://ca.example/acct/operator"
$env:MODERN_PKI_PUBLIC_TLS_CAA_VALIDATION_METHOD = "http-01"
$env:MODERN_PKI_PUBLIC_TLS_CAA_RESOLVER = "resolver.example.internal:53"
$env:MODERN_PKI_PUBLIC_TLS_CAA_ALLOW_DNSSEC_INDETERMINATE = "false"
```

Only set `MODERN_PKI_TRUSTED_PROXIES` when the service sits behind a trusted
proxy that sets `X-Forwarded-For`. Use exact proxy IPs or CIDR ranges.

## Startup Checks

Before allowing traffic, verify:

1. `MODERN_PKI_ENV=production` starts without rejecting auth, pepper,
   bootstrap, or nonce config.
2. `GET /readyz` succeeds.
3. `GET /version` returns the expected build metadata.
4. `GET /trust/anchors` returns expected trust anchors.
5. `GET /issuers/{id}/crl` returns the latest CRL for every active issuer.
6. A known-good OCSP request returns `successful`.
7. `POST /audit-events/repair/issuance` returns zero repairs after restore or
   migration checks.

## Deployment Steps

1. Build and test the release artifact.
2. Back up the database and verify key-provider access.
3. Apply service deployment with production env vars from a secret manager.
4. Start one node and wait for `GET /readyz`.
5. Run smoke checks for health, readiness, trust anchors, CRL, OCSP, and one
   non-production issuance profile.
6. Start remaining nodes.
7. Confirm outbox and expiration scan workers are running on the intended nodes.
8. Remove any temporary bootstrap API key from runtime config after operator
   keys exist.

## Do Not Enable In Production

- `MODERN_PKI_AUTH_MODE=dev`
- `MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS=true`
- `MODERN_PKI_ACME_HTTP01_BASE_URL`
- weak or checked-in API keys, API peppers, webhook secrets, DB passwords, or
  issuer key material
- memory ACME nonce store on multi-node or production deployments

## Rollback

Prefer roll-forward. If rollback is required, follow
[Production Recovery Runbook](production-recovery.md). Do not edit
`schema_migrations` manually and do not replay all outbox rows blindly.
