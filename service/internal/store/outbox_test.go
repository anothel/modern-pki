package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	_ "modernc.org/sqlite"
)

func TestMemoryStoreOutboxAndJobAttempts(t *testing.T) {
	testOutboxAndJobAttempts(t, NewMemoryStore())
}

func TestSQLStoreOutboxAndJobAttempts(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxAndJobAttempts(t, NewSQLStore(db))
}

func TestSQLStoreOCSPResponders(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}

	repo := NewSQLStore(db)
	issuer := domain.Issuer{
		ID:             "issuer-1",
		Name:           "Issuer",
		Kind:           domain.IssuerIntermediateCA,
		Status:         domain.IssuerActive,
		CertificatePEM: "issuer-pem",
		KeyRef:         "issuer-key",
		CreatedAt:      time.Unix(10, 0),
		UpdatedAt:      time.Unix(10, 0),
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	first := domain.OCSPResponder{
		ID:             "responder-1",
		IssuerID:       issuer.ID,
		Name:           "old",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "old-pem",
		KeyRef:         "old-key",
		CreatedAt:      time.Unix(20, 0),
		UpdatedAt:      time.Unix(20, 0),
	}
	second := domain.OCSPResponder{
		ID:             "responder-2",
		IssuerID:       issuer.ID,
		Name:           "new",
		Status:         domain.OCSPResponderActive,
		CertificatePEM: "new-pem",
		KeyRef:         "new-key",
		CreatedAt:      time.Unix(30, 0),
		UpdatedAt:      time.Unix(30, 0),
	}
	if err := repo.CreateOCSPResponder(ctx, first); err != nil {
		t.Fatalf("CreateOCSPResponder first returned error: %v", err)
	}
	if err := repo.CreateOCSPResponder(ctx, second); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("CreateOCSPResponder second error = %v, want ErrInvalidTransition", err)
	}

	active, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != first.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, first.ID)
	}
	stored, err := repo.GetOCSPResponder(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetOCSPResponder returned error: %v", err)
	}
	stored.Status = domain.OCSPResponderDisabled
	stored.UpdatedAt = time.Unix(25, 0)
	if err := repo.UpdateOCSPResponderIfStatus(ctx, stored, domain.OCSPResponderActive); err != nil {
		t.Fatalf("UpdateOCSPResponderIfStatus returned error: %v", err)
	}
	if _, err := repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID); !errors.Is(err, domain.ErrOCSPResponderNotFound) {
		t.Fatalf("GetActiveOCSPResponderByIssuer error = %v, want ErrOCSPResponderNotFound", err)
	}
	if err := repo.CreateOCSPResponder(ctx, second); err != nil {
		t.Fatalf("CreateOCSPResponder second after disable returned error: %v", err)
	}

	list, err := repo.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("responder count = %d, want 2", len(list))
	}
	if list[0].ID != first.ID || list[1].ID != second.ID {
		t.Fatalf("responders = %#v, want creation order [%q, %q]", list, first.ID, second.ID)
	}
	if list[0].Status != domain.OCSPResponderDisabled || list[1].Status != domain.OCSPResponderActive {
		t.Fatalf("responder statuses = %#v", list)
	}
}

func TestMemoryStoreCertificateExpirationScan(t *testing.T) {
	testCertificateExpirationScan(t, NewMemoryStore())
}

func TestSQLStoreCertificateExpirationScan(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testCertificateExpirationScan(t, NewSQLStore(db))
}

func testOutboxAndJobAttempts(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	ready := domain.OutboxMessage{
		ID:          "outbox-ready",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now.Add(-time.Minute),
		CreatedAt:   now.Add(-time.Minute),
		UpdatedAt:   now.Add(-time.Minute),
	}
	future := domain.OutboxMessage{
		ID:          "outbox-future",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-2"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now.Add(time.Hour),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := repo.CreateOutboxMessage(ctx, future); err != nil {
		t.Fatalf("CreateOutboxMessage future returned error: %v", err)
	}
	if err := repo.CreateOutboxMessage(ctx, ready); err != nil {
		t.Fatalf("CreateOutboxMessage ready returned error: %v", err)
	}

	due, err := repo.ListDueOutboxMessages(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 1 || due[0].ID != ready.ID {
		t.Fatalf("due messages = %#v, want only ready", due)
	}

	processing := ready
	processing.Status = domain.OutboxProcessing
	processing.UpdatedAt = now
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, processing, domain.OutboxPending); err != nil {
		t.Fatalf("UpdateOutboxMessageStatusIfStatus returned error: %v", err)
	}
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, ready, domain.OutboxPending); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateOutboxMessageStatusIfStatus error = %v, want ErrInvalidTransition", err)
	}

	attempt := domain.JobAttempt{
		ID:              "attempt-1",
		OutboxMessageID: ready.ID,
		Status:          domain.JobAttemptFailed,
		Error:           "timeout",
		StartedAt:       now,
		FinishedAt:      now.Add(time.Second),
		CreatedAt:       now,
	}
	if err := repo.CreateJobAttempt(ctx, attempt); err != nil {
		t.Fatalf("CreateJobAttempt returned error: %v", err)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, ready.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].ID != attempt.ID || attempts[0].Error != "timeout" {
		t.Fatalf("job attempts = %#v", attempts)
	}
}

func testCertificateExpirationScan(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	warningBefore := now.Add(24 * time.Hour)

	certificates := []domain.Certificate{
		expirationScanCertificate("expired-suspended", domain.CertificateSuspended, now.Add(-2*time.Hour), time.Time{}),
		expirationScanCertificate("expired-valid", domain.CertificateValid, now.Add(-time.Hour), time.Time{}),
		expirationScanCertificate("warning-valid", domain.CertificateValid, now.Add(2*time.Hour), time.Time{}),
		expirationScanCertificate("warning-notified", domain.CertificateValid, now.Add(3*time.Hour), now.Add(-time.Hour)),
		expirationScanCertificate("outside-valid", domain.CertificateValid, now.Add(72*time.Hour), time.Time{}),
		expirationScanCertificate("expired-revoked", domain.CertificateRevoked, now.Add(-time.Hour), time.Time{}),
	}
	for _, certificate := range certificates {
		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			t.Fatalf("CreateCertificate(%s) returned error: %v", certificate.ID, err)
		}
	}

	candidates, err := repo.ListCertificatesForExpirationScan(ctx, now, warningBefore, 10)
	if err != nil {
		t.Fatalf("ListCertificatesForExpirationScan returned error: %v", err)
	}
	wantIDs := []string{"expired-suspended", "expired-valid", "warning-valid"}
	if len(candidates) != len(wantIDs) {
		t.Fatalf("candidate count = %d, want %d: %#v", len(candidates), len(wantIDs), candidates)
	}
	for i, want := range wantIDs {
		if candidates[i].ID != want {
			t.Fatalf("candidate %d ID = %q, want %q; candidates=%#v", i, candidates[i].ID, want, candidates)
		}
	}

	limited, err := repo.ListCertificatesForExpirationScan(ctx, now, warningBefore, 2)
	if err != nil {
		t.Fatalf("limited ListCertificatesForExpirationScan returned error: %v", err)
	}
	if len(limited) != 2 || limited[0].ID != "expired-suspended" || limited[1].ID != "expired-valid" {
		t.Fatalf("limited candidates = %#v", limited)
	}

	warning := candidates[2]
	warning.RenewalNotifiedAt = now
	warning.UpdatedAt = now
	if err := repo.UpdateCertificateIfStatus(ctx, warning, domain.CertificateValid); err != nil {
		t.Fatalf("UpdateCertificateIfStatus warning returned error: %v", err)
	}
	stored, err := repo.GetCertificate(ctx, warning.ID)
	if err != nil {
		t.Fatalf("GetCertificate warning returned error: %v", err)
	}
	if !stored.RenewalNotifiedAt.Equal(now) {
		t.Fatalf("RenewalNotifiedAt = %s, want %s", stored.RenewalNotifiedAt, now)
	}
}

func expirationScanCertificate(id string, status domain.CertificateStatus, notAfter time.Time, renewalNotifiedAt time.Time) domain.Certificate {
	createdAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	return domain.Certificate{
		ID:                id,
		IdentityID:        "identity-" + id,
		IssuerID:          "issuer-1",
		EnrollmentID:      "enrollment-" + id,
		SerialNumber:      "serial-" + id,
		Subject:           "CN=" + id,
		NotBefore:         createdAt,
		NotAfter:          notAfter,
		Status:            status,
		CertificatePEM:    "cert-pem-" + id,
		RenewalNotifiedAt: renewalNotifiedAt,
		CreatedAt:         createdAt,
		UpdatedAt:         createdAt,
	}
}
