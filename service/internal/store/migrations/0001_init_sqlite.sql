CREATE TABLE IF NOT EXISTS identities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    name TEXT NOT NULL,
    external_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS issuers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ocsp_responders (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    key_ref TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ocsp_responders_issuer_active
    ON ocsp_responders(issuer_id, status, created_at, id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ocsp_responders_single_active
    ON ocsp_responders(issuer_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS notification_endpoints (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    status TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    event_types TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notification_endpoints_status
    ON notification_endpoints(status, created_at, id);

CREATE TABLE IF NOT EXISTS certificate_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    validity_period_seconds INTEGER NOT NULL,
    subject_template TEXT NOT NULL,
    allowed_dns_patterns TEXT NOT NULL,
    allowed_ip_ranges TEXT NOT NULL,
    key_usage TEXT NOT NULL,
    extended_key_usage TEXT NOT NULL,
    basic_constraints TEXT NOT NULL,
    subject_key_identifier INTEGER NOT NULL,
    authority_key_identifier INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    certificate_profile_id TEXT NOT NULL,
    csr_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_subject TEXT NOT NULL,
    requested_dns_names TEXT NOT NULL,
    requested_ip_addresses TEXT NOT NULL,
    csr_dns_names TEXT NOT NULL,
    csr_ip_addresses TEXT NOT NULL,
    requested_not_after TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id),
    certificate_profile_id TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    subject TEXT NOT NULL,
    dns_names TEXT NOT NULL,
    ip_addresses TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
    renewal_notified_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revocations (
    id TEXT PRIMARY KEY,
    certificate_id TEXT NOT NULL REFERENCES certificates(id),
    reason TEXT NOT NULL,
    revoked_by TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crl_publications (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    distribution_point TEXT NOT NULL,
    crl_number INTEGER NOT NULL,
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    status TEXT NOT NULL,
    crl_pem TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox_messages (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    available_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_messages_due
    ON outbox_messages(status, available_at, created_at, id);

CREATE TABLE IF NOT EXISTS job_attempts (
    id TEXT PRIMARY KEY,
    outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
    status TEXT NOT NULL,
    error TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_attempts_outbox_message
    ON job_attempts(outbox_message_id, created_at, id);
