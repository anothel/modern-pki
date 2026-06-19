package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	_ "modernc.org/sqlite"
)

func TestApplyInitialMigrationUpgradesLegacySQLiteColumns(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	_, err = db.ExecContext(ctx, `
CREATE TABLE certificate_profiles (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
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
CREATE TABLE enrollments (
	id TEXT PRIMARY KEY,
	identity_id TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
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
CREATE TABLE certificates (
	id TEXT PRIMARY KEY,
	identity_id TEXT NOT NULL,
	issuer_id TEXT NOT NULL,
	enrollment_id TEXT NOT NULL,
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
);`)
	if err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}

	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	for _, tt := range []struct {
		table string
		name  string
	}{
		{table: "certificate_profiles", name: "subject_key_identifier"},
		{table: "certificate_profiles", name: "authority_key_identifier"},
		{table: "enrollments", name: "certificate_profile_id"},
		{table: "certificates", name: "certificate_profile_id"},
		{table: "certificates", name: "renewal_notified_at"},
	} {
		if !testSQLiteColumnExists(t, db, tt.table, tt.name) {
			t.Fatalf("column %s.%s does not exist after migration", tt.table, tt.name)
		}
	}
	for _, table := range []string{"ocsp_responders", "outbox_messages", "job_attempts"} {
		if !testSQLiteTableExists(t, db, table) {
			t.Fatalf("table %s does not exist after migration", table)
		}
	}
}

func TestUnmarshalBasicConstraintsPolicyNormalizesLegacyLeafPathLen(t *testing.T) {
	var policy domain.BasicConstraintsPolicy
	if err := unmarshalBasicConstraintsPolicy(`{"critical":true,"ca":false,"max_path_len":0}`, &policy); err != nil {
		t.Fatalf("unmarshalBasicConstraintsPolicy returned error: %v", err)
	}
	if policy.MaxPathLen != nil {
		t.Fatalf("leaf legacy MaxPathLen = %#v, want nil", policy.MaxPathLen)
	}

	var caPolicy domain.BasicConstraintsPolicy
	if err := unmarshalBasicConstraintsPolicy(`{"critical":true,"ca":true,"max_path_len":0}`, &caPolicy); err != nil {
		t.Fatalf("unmarshalBasicConstraintsPolicy CA returned error: %v", err)
	}
	if caPolicy.MaxPathLen == nil || *caPolicy.MaxPathLen != 0 {
		t.Fatalf("CA MaxPathLen = %#v, want pointer to 0", caPolicy.MaxPathLen)
	}
}

func testSQLiteColumnExists(t *testing.T, db *sql.DB, table string, name string) bool {
	t.Helper()

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
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
			t.Fatalf("scan PRAGMA table_info(%s): %v", table, err)
		}
		if columnName == name {
			return true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate PRAGMA table_info(%s): %v", table, err)
	}
	return false
}

func testSQLiteTableExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()

	var name string
	err := db.QueryRow("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	if err != nil {
		t.Fatalf("query sqlite_master for %s: %v", table, err)
	}
	return name == table
}
