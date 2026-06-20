package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
)

//go:embed migrations/0001_init.sql migrations/0001_init_sqlite.sql
var migrationFiles embed.FS

func ApplyInitialMigration(ctx context.Context, db *sql.DB, driver string) error {
	path, err := initialMigrationPath(driver)
	if err != nil {
		return err
	}

	sqlBytes, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read initial migration: %w", err)
	}

	if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("execute initial migration: %w", err)
	}
	if err := applyCompatibilityMigrations(ctx, db, driver); err != nil {
		return err
	}
	return nil
}

func initialMigrationPath(driver string) (string, error) {
	switch driver {
	case "sqlite":
		return "migrations/0001_init_sqlite.sql", nil
	case "pgx":
		return "migrations/0001_init.sql", nil
	default:
		return "", fmt.Errorf("unsupported database driver %q", driver)
	}
}

func applyCompatibilityMigrations(ctx context.Context, db *sql.DB, driver string) error {
	switch driver {
	case "sqlite":
		return applySQLiteCompatibilityMigrations(ctx, db)
	case "pgx":
		return applyPostgresCompatibilityMigrations(ctx, db)
	default:
		return fmt.Errorf("unsupported database driver %q", driver)
	}
}

func applySQLiteCompatibilityMigrations(ctx context.Context, db *sql.DB) error {
	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{table: "issuers", name: "parent_issuer_id", definition: "parent_issuer_id TEXT NOT NULL DEFAULT ''"},
		{table: "issuers", name: "aia_url", definition: "aia_url TEXT NOT NULL DEFAULT ''"},
		{table: "issuers", name: "crl_distribution_points", definition: "crl_distribution_points TEXT NOT NULL DEFAULT '[]'"},
		{table: "issuers", name: "trust_anchor", definition: "trust_anchor INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "subject_key_identifier", definition: "subject_key_identifier INTEGER NOT NULL DEFAULT 0"},
		{table: "certificate_profiles", name: "authority_key_identifier", definition: "authority_key_identifier INTEGER NOT NULL DEFAULT 0"},
		{table: "enrollments", name: "certificate_profile_id", definition: "certificate_profile_id TEXT NOT NULL DEFAULT ''"},
		{table: "certificates", name: "certificate_profile_id", definition: "certificate_profile_id TEXT NOT NULL DEFAULT ''"},
		{table: "certificates", name: "renewal_notified_at", definition: "renewal_notified_at TEXT"},
	}

	for _, column := range columns {
		exists, err := sqliteColumnExists(ctx, db, column.table, column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", column.table, column.definition)); err != nil {
			return fmt.Errorf("add sqlite column %s.%s: %w", column.table, column.name, err)
		}
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS outbox_messages (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL,
			available_at TEXT NOT NULL,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_due
			ON outbox_messages(status, available_at, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS job_attempts (
			id TEXT PRIMARY KEY,
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			status TEXT NOT NULL,
			error TEXT NOT NULL,
			started_at TEXT NOT NULL,
			finished_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_attempts_outbox_message
			ON job_attempts(outbox_message_id, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_expiration_scan
			ON certificates(status, not_after, renewal_notified_at, id)`,
		`CREATE TABLE IF NOT EXISTS notification_endpoints (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL DEFAULT '',
			event_types TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_notification_endpoints_status
			ON notification_endpoints(status, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			actor TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT '["operator"]',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_token_hash
			ON api_keys(token_hash)`,
		`CREATE TABLE IF NOT EXISTS acme_accounts (
			id TEXT PRIMARY KEY,
			contacts TEXT NOT NULL,
			status TEXT NOT NULL,
			terms_of_service_agreed INTEGER NOT NULL,
			key_thumbprint TEXT NOT NULL DEFAULT '',
			key_jwk_json TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS acme_orders (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id),
			identity_id TEXT NOT NULL REFERENCES identities(id),
			issuer_id TEXT NOT NULL REFERENCES issuers(id),
			certificate_profile_id TEXT NOT NULL,
			status TEXT NOT NULL,
			csr_pem TEXT NOT NULL,
			requested_subject TEXT NOT NULL,
			requested_dns_names TEXT NOT NULL,
			requested_ip_addresses TEXT NOT NULL,
			requested_not_after TEXT NOT NULL,
			enrollment_id TEXT NOT NULL,
			certificate_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account
			ON acme_orders(account_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id),
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_order
			ON acme_authorizations(order_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_challenges (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL REFERENCES acme_authorizations(id),
			type TEXT NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL,
			validated_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authorization
			ON acme_challenges(authorization_id, created_at, id)`,
		`UPDATE issuers
			SET trust_anchor = 1
			WHERE kind = 'root_ca' AND trust_anchor = 0`,
	}
	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("execute sqlite compatibility migration: %w", err)
		}
	}
	outboxColumns := []struct {
		name       string
		definition string
	}{
		{name: "attempt_count", definition: "attempt_count INTEGER NOT NULL DEFAULT 0"},
		{name: "max_attempts", definition: "max_attempts INTEGER NOT NULL DEFAULT 0"},
		{name: "last_error", definition: "last_error TEXT NOT NULL DEFAULT ''"},
	}
	for _, column := range outboxColumns {
		exists, err := sqliteColumnExists(ctx, db, "outbox_messages", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE outbox_messages ADD COLUMN %s", column.definition)); err != nil {
			return fmt.Errorf("add sqlite column outbox_messages.%s: %w", column.name, err)
		}
	}
	if exists, err := sqliteColumnExists(ctx, db, "notification_endpoints", "secret"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, "ALTER TABLE notification_endpoints ADD COLUMN secret TEXT NOT NULL DEFAULT ''"); err != nil {
			return fmt.Errorf("add sqlite column notification_endpoints.secret: %w", err)
		}
	}
	if exists, err := sqliteColumnExists(ctx, db, "api_keys", "scopes"); err != nil {
		return err
	} else if !exists {
		if _, err := db.ExecContext(ctx, `ALTER TABLE api_keys ADD COLUMN scopes TEXT NOT NULL DEFAULT '["operator"]'`); err != nil {
			return fmt.Errorf("add sqlite column api_keys.scopes: %w", err)
		}
	}
	for _, column := range []struct {
		name       string
		definition string
	}{
		{name: "key_thumbprint", definition: "key_thumbprint TEXT NOT NULL DEFAULT ''"},
		{name: "key_jwk_json", definition: "key_jwk_json TEXT NOT NULL DEFAULT ''"},
	} {
		exists, err := sqliteColumnExists(ctx, db, "acme_accounts", column.name)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE acme_accounts ADD COLUMN %s", column.definition)); err != nil {
			return fmt.Errorf("add sqlite column acme_accounts.%s: %w", column.name, err)
		}
	}
	return nil
}

func sqliteColumnExists(ctx context.Context, db *sql.DB, table string, name string) (bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return false, fmt.Errorf("inspect sqlite table %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var columnName string
		var columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return false, fmt.Errorf("scan sqlite table %s: %w", table, err)
		}
		if columnName == name {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("inspect sqlite table %s: %w", table, err)
	}
	return false, nil
}

func applyPostgresCompatibilityMigrations(ctx context.Context, db *sql.DB) error {
	statements := []string{
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS subject_key_identifier BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS parent_issuer_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS aia_url TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS crl_distribution_points TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE issuers ADD COLUMN IF NOT EXISTS trust_anchor BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE certificate_profiles ADD COLUMN IF NOT EXISTS authority_key_identifier BOOLEAN NOT NULL DEFAULT FALSE",
		"ALTER TABLE enrollments ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS certificate_profile_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE certificates ADD COLUMN IF NOT EXISTS renewal_notified_at TIMESTAMPTZ",
		`CREATE TABLE IF NOT EXISTS outbox_messages (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL,
			available_at TIMESTAMPTZ NOT NULL,
			attempt_count INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS max_attempts INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE outbox_messages ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT ''",
		`CREATE INDEX IF NOT EXISTS idx_outbox_messages_due
			ON outbox_messages(status, available_at, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS job_attempts (
			id TEXT PRIMARY KEY,
			outbox_message_id TEXT NOT NULL REFERENCES outbox_messages(id),
			status TEXT NOT NULL,
			error TEXT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL,
			finished_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_job_attempts_outbox_message
			ON job_attempts(outbox_message_id, created_at, id)`,
		`CREATE INDEX IF NOT EXISTS idx_certificates_expiration_scan
			ON certificates(status, not_after, renewal_notified_at, id)`,
		`CREATE TABLE IF NOT EXISTS notification_endpoints (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT NOT NULL,
			status TEXT NOT NULL,
			url TEXT NOT NULL,
			secret TEXT NOT NULL DEFAULT '',
			event_types TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE notification_endpoints ADD COLUMN IF NOT EXISTS secret TEXT NOT NULL DEFAULT ''",
		`CREATE INDEX IF NOT EXISTS idx_notification_endpoints_status
			ON notification_endpoints(status, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			status TEXT NOT NULL,
			actor TEXT NOT NULL,
			scopes TEXT NOT NULL DEFAULT '["operator"]',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS scopes TEXT NOT NULL DEFAULT '["operator"]'`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_token_hash
			ON api_keys(token_hash)`,
		`CREATE TABLE IF NOT EXISTS acme_accounts (
			id TEXT PRIMARY KEY,
			contacts TEXT NOT NULL,
			status TEXT NOT NULL,
			terms_of_service_agreed BOOLEAN NOT NULL,
			key_thumbprint TEXT NOT NULL DEFAULT '',
			key_jwk_json TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		"ALTER TABLE acme_accounts ADD COLUMN IF NOT EXISTS key_thumbprint TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE acme_accounts ADD COLUMN IF NOT EXISTS key_jwk_json TEXT NOT NULL DEFAULT ''",
		`CREATE TABLE IF NOT EXISTS acme_orders (
			id TEXT PRIMARY KEY,
			account_id TEXT NOT NULL REFERENCES acme_accounts(id),
			identity_id TEXT NOT NULL REFERENCES identities(id),
			issuer_id TEXT NOT NULL REFERENCES issuers(id),
			certificate_profile_id TEXT NOT NULL,
			status TEXT NOT NULL,
			csr_pem TEXT NOT NULL,
			requested_subject TEXT NOT NULL,
			requested_dns_names TEXT NOT NULL,
			requested_ip_addresses TEXT NOT NULL,
			requested_not_after TIMESTAMPTZ NOT NULL,
			enrollment_id TEXT NOT NULL,
			certificate_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_orders_account
			ON acme_orders(account_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_authorizations (
			id TEXT PRIMARY KEY,
			order_id TEXT NOT NULL REFERENCES acme_orders(id),
			identifier_type TEXT NOT NULL,
			identifier_value TEXT NOT NULL,
			status TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_authorizations_order
			ON acme_authorizations(order_id, created_at, id)`,
		`CREATE TABLE IF NOT EXISTS acme_challenges (
			id TEXT PRIMARY KEY,
			authorization_id TEXT NOT NULL REFERENCES acme_authorizations(id),
			type TEXT NOT NULL,
			token TEXT NOT NULL,
			status TEXT NOT NULL,
			validated_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_acme_challenges_authorization
			ON acme_challenges(authorization_id, created_at, id)`,
		`UPDATE issuers
			SET trust_anchor = TRUE
			WHERE kind = 'root_ca' AND trust_anchor = FALSE`,
	}

	for _, statement := range statements {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("execute postgres compatibility migration: %w", err)
		}
	}
	return nil
}
