package httpapi

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

type SQLACMENonceStore struct {
	db     *sql.DB
	driver string
}

func NewSQLACMENonceStore(db *sql.DB, driver string) *SQLACMENonceStore {
	return &SQLACMENonceStore{db: db, driver: driver}
}

func (s *SQLACMENonceStore) Issue(ctx context.Context, nonce string, issuedAt time.Time, expiresAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, s.query(`DELETE FROM acme_nonces WHERE expires_at <= ?`), issuedAt); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, s.query(`
INSERT INTO acme_nonces (nonce, issued_at, expires_at)
VALUES (?, ?, ?)
`), nonce, issuedAt, expiresAt)
	return err
}

func (s *SQLACMENonceStore) Consume(ctx context.Context, nonce string, now time.Time) (bool, error) {
	result, err := s.db.ExecContext(ctx, s.query(`
DELETE FROM acme_nonces
WHERE nonce = ? AND expires_at > ?
`), nonce, now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

func (s *SQLACMENonceStore) query(query string) string {
	if s.driver == "sqlite" {
		return query
	}
	var index int
	return replaceQuestionPlaceholders(query, func() string {
		index++
		return fmt.Sprintf("$%d", index)
	})
}

func replaceQuestionPlaceholders(query string, next func() string) string {
	var b strings.Builder
	for _, r := range query {
		if r == '?' {
			b.WriteString(next())
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
