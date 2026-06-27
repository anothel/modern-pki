# Audit Metadata Contract

Audit events are append-only operational records. `audit_events.metadata_json` is structured JSON, not debug text.

## Common Fields

Every audit metadata object includes:

```text
result_code
```

Successful lifecycle events use:

```text
result_code = ok
```

Failed API request events use:

```text
result_code = error
error_code
http_method
http_path
http_status
```

When the request context carries them, metadata also includes:

```text
request_id
traceparent
client_ip
user_agent
auth_method
elapsed_ms
```

`traceparent` preserves the inbound W3C trace context header when present. The
service records it as correlation metadata only; it does not create or export
spans.

API key authenticated requests also include:

```text
api_key_id
api_key_name
api_key_actor
api_key_fingerprint
api_key_scopes
```

Lifecycle status changes include:

```text
previous_status
new_status
```

Revocation events also include:

```text
revocation_reason
```

Metadata values are redacted when the field name contains:

```text
secret
token
password
private_key
```

## Query And Retention

`GET /audit-events` supports exact filters:

```text
actor
action
resource_type
resource_id
from
to
sort
limit
offset
```

`from` and `to` use RFC3339 timestamps. `sort` accepts `asc` and `desc`.
`offset` requires `limit`.

Retention pruning is explicit:

```text
POST /audit-events/retention/prune
{"before":"2026-01-01T00:00:00Z"}
```

The cutoff must be before service current time. The service writes an
`audit.retention_pruned` event after deleting older audit rows.

## Lifecycle Identity Fields

Use stable snake_case IDs:

```text
issuer_id
identity_id
enrollment_id
certificate_id
serial_number
profile_id
crl_publication_id
ocsp_responder_id
```

Certificate lifecycle events with a profile-backed certificate include `profile_id`.

Certificate expiration scan events include:

```text
certificate.expired
certificate.expiration_warning
```

These events include:

```text
certificate_id
serial_number
issuer_id
identity_id
enrollment_id
profile_id
not_after
warning_window_seconds
```

## Protocol Fields

CRL publication events include:

```text
distribution_point
crl_number
```

OCSP request events include:

```text
request_type
issuer_id
requested_cert_count
response_status
first_serial_number
first_certificate_status
certificates
responder_mode
responder_id
```

Each OCSP certificate entry includes serial and issuer hashes, plus status-specific fields.

Responder values are:

```text
responder_mode = delegated
responder_id = <ocsp responder id>
```

or:

```text
responder_mode = issuer_direct
responder_id omitted
```

OCSP responder registration events include:

```text
issuer_id
ocsp_responder_id
```

OCSP responder disable events include:

```text
issuer_id
ocsp_responder_id
```

OCSP responder rotation emits two existing lifecycle events in order:

```text
ocsp_responder.disabled
ocsp_responder.created
```

## Error Codes

Current stable error codes:

```text
invalid_request
unsupported_media_type
unauthorized
forbidden
rate_limited
invalid_lifecycle_transition
identity_not_found
issuer_not_found
ocsp_responder_not_found
notification_endpoint_not_found
certificate_profile_not_found
enrollment_not_found
certificate_not_found
crl_publication_not_found
outbox_message_not_found
api_key_not_found
acme_account_not_found
acme_account_deactivated
acme_order_not_found
acme_authorization_not_found
acme_challenge_not_found
csr_parse_failed
certificate_issuance_failed
crl_generation_failed
ocsp_decode_failed
ocsp_responder_validation_failed
ocsp_response_failed
storage_failure
internal
```
