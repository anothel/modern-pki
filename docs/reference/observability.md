# Observability Reference

`modern-pki-service` exposes low-cardinality process metrics and emits
structured JSON startup logs using only the Go standard library.

## Metrics

Metrics are exposed at:

```text
GET /debug/vars
```

The endpoint is registered on the service mux. Protect it at the deployment
gateway if the service is reachable outside a trusted operator network.

### Counters

`modern_pki_http_requests_total` is an expvar map keyed by:

```text
<boundary>:<http_status>
```

Current boundary values include:

```text
identity
issuer
profile
enrollment
issuance
certificate
revocation
renewal
reissue
suspension
crl
ocsp
acme
webhook
outbox
auth
audit
operator
expiration_scan
observability
```

`modern_pki_http_events_total` records event counters:

```text
auth:failure
rate_limit:acme_account
rate_limit:acme_order
rate_limit:acme_challenge
rate_limit:acme_finalize
```

These counters are process-local. Use the deployment platform or metrics
collector to scrape every service node.

## Structured Logs

Startup and worker lifecycle logs are JSON objects with an `event` field.
Examples:

```json
{"event":"service.listening","addr":":8080"}
{"event":"outbox_worker.enabled","interval":"5s","batch":10}
```

The structured log helper redacts fields whose names contain:

```text
secret
token
password
pepper
private_key
```

Do not rely on this as the only secret control. Never pass raw key material,
API tokens, webhook secrets, database passwords, or private keys to logs.

## Request Correlation

HTTP responses include `X-Request-ID`. If the request supplies `X-Request-ID`,
the service preserves it. Otherwise the service generates one. Audit metadata
records `request_id`, `client_ip`, and `elapsed_ms` when request context is
available.

`X-Forwarded-For` is trusted only when the direct peer matches
`MODERN_PKI_TRUSTED_PROXIES`.

## Remaining Gaps

- DB, signer, and core CLI latency/error histograms are not implemented yet.
- Distributed trace/span propagation is not implemented beyond request ID
  correlation.
- Audit retention policy, tamper-evident storage, and SIEM export examples are
  separate roadmap items.
