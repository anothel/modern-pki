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
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    identity_id TEXT NOT NULL REFERENCES identities(id),
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
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
    serial_number TEXT NOT NULL,
    subject TEXT NOT NULL,
    dns_names TEXT NOT NULL,
    ip_addresses TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    status TEXT NOT NULL,
    certificate_pem TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
