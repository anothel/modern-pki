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

func TestSQLStoreIdentityPolicyFieldsRoundTrip(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testIdentityPolicyFieldsRoundTrip(t, NewSQLStore(db))
}

func TestMemoryStoreAPIKeys(t *testing.T) {
	testAPIKeys(t, NewMemoryStore())
}

func TestSQLStoreAPIKeys(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testAPIKeys(t, NewSQLStore(db))
}

func TestMemoryStoreOutboxRetryMetadata(t *testing.T) {
	testOutboxRetryMetadata(t, NewMemoryStore())
}

func TestSQLStoreOutboxRetryMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxRetryMetadata(t, NewSQLStore(db))
}

func TestMemoryStoreOutboxLeaseRecovery(t *testing.T) {
	testOutboxLeaseRecovery(t, NewMemoryStore())
}

func TestSQLStoreOutboxLeaseRecovery(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testOutboxLeaseRecovery(t, NewSQLStore(db))
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

func TestMemoryStoreIssuerTrustMetadata(t *testing.T) {
	testIssuerTrustMetadata(t, NewMemoryStore())
}

func TestSQLStoreIssuerTrustMetadata(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testIssuerTrustMetadata(t, NewSQLStore(db))
}

func TestMemoryStoreACMEState(t *testing.T) {
	testACMEState(t, NewMemoryStore())
}

func TestSQLStoreACMEState(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testACMEState(t, NewSQLStore(db))
}

func TestMemoryStoreRejectsDuplicateACMEAccountThumbprint(t *testing.T) {
	testRejectsDuplicateACMEAccountThumbprint(t, NewMemoryStore())
}

func TestSQLStoreRejectsDuplicateACMEAccountThumbprint(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testRejectsDuplicateACMEAccountThumbprint(t, NewSQLStore(db))
}

func TestMemoryStoreRejectsDuplicateCRLPublicationNumber(t *testing.T) {
	testRejectsDuplicateCRLPublicationNumber(t, NewMemoryStore())
}

func TestSQLStoreRejectsDuplicateCRLPublicationNumber(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testRejectsDuplicateCRLPublicationNumber(t, NewSQLStore(db))
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

func TestMemoryStoreNotificationEndpoints(t *testing.T) {
	testNotificationEndpoints(t, NewMemoryStore())
}

func TestSQLStoreNotificationEndpoints(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	if err := ApplyInitialMigration(ctx, db, "sqlite"); err != nil {
		t.Fatalf("ApplyInitialMigration returned error: %v", err)
	}
	testNotificationEndpoints(t, NewSQLStore(db))
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

func testOutboxRetryMetadata(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	message := domain.OutboxMessage{
		ID:           "outbox-retry",
		Type:         "certificate.expiration_warning",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxPending,
		AvailableAt:  now,
		AttemptCount: 2,
		MaxAttempts:  5,
		LastError:    "previous failure",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	stored, err := repo.GetOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("GetOutboxMessage returned error: %v", err)
	}
	if stored.AttemptCount != 2 || stored.MaxAttempts != 5 || stored.LastError != "previous failure" {
		t.Fatalf("stored retry metadata = %#v", stored)
	}

	stored.Status = domain.OutboxDeadLetter
	stored.AttemptCount = 5
	stored.LastError = "max attempts exceeded"
	stored.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, stored, domain.OutboxPending); err != nil {
		t.Fatalf("UpdateOutboxMessageStatusIfStatus returned error: %v", err)
	}

	pending, err := repo.ListOutboxMessages(ctx, domain.OutboxPending)
	if err != nil {
		t.Fatalf("ListOutboxMessages pending returned error: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending messages = %#v, want none", pending)
	}
	dead, err := repo.ListOutboxMessages(ctx, domain.OutboxDeadLetter)
	if err != nil {
		t.Fatalf("ListOutboxMessages dead_letter returned error: %v", err)
	}
	if len(dead) != 1 || dead[0].ID != message.ID || dead[0].AttemptCount != 5 || dead[0].LastError != "max attempts exceeded" {
		t.Fatalf("dead letter messages = %#v", dead)
	}
}

func testOutboxLeaseRecovery(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	active := domain.OutboxMessage{
		ID:                   "outbox-active",
		Type:                 "certificate.expiration_warning",
		PayloadJSON:          `{"certificate_id":"cert-active"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          now.Add(-time.Hour),
		ProcessingDeadlineAt: now.Add(time.Minute),
		CreatedAt:            now.Add(-time.Hour),
		UpdatedAt:            now.Add(-time.Minute),
	}
	expired := domain.OutboxMessage{
		ID:                   "outbox-expired",
		Type:                 "certificate.expiration_warning",
		PayloadJSON:          `{"certificate_id":"cert-expired"}`,
		Status:               domain.OutboxProcessing,
		AvailableAt:          now.Add(-time.Hour),
		ProcessingDeadlineAt: now.Add(-time.Minute),
		CreatedAt:            now.Add(-2 * time.Hour),
		UpdatedAt:            now.Add(-time.Hour),
	}
	if err := repo.CreateOutboxMessage(ctx, active); err != nil {
		t.Fatalf("CreateOutboxMessage active returned error: %v", err)
	}
	if err := repo.CreateOutboxMessage(ctx, expired); err != nil {
		t.Fatalf("CreateOutboxMessage expired returned error: %v", err)
	}

	due, err := repo.ListDueOutboxMessages(ctx, now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 1 || due[0].ID != expired.ID || due[0].Status != domain.OutboxProcessing {
		t.Fatalf("due messages = %#v, want only expired processing message", due)
	}
}

func testNotificationEndpoints(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	first := domain.NotificationEndpoint{
		ID:         "endpoint-1",
		Name:       "ops",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        "https://ops.example.test/hooks/pki",
		Secret:     "secret-1",
		EventTypes: []string{"certificate.expiration_warning", "certificate.expired"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	second := domain.NotificationEndpoint{
		ID:         "endpoint-2",
		Name:       "all-events",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        "https://ops.example.test/hooks/all",
		Secret:     "secret-2",
		EventTypes: nil,
		CreatedAt:  now.Add(time.Second),
		UpdatedAt:  now.Add(time.Second),
	}
	if err := repo.CreateNotificationEndpoint(ctx, second); err != nil {
		t.Fatalf("CreateNotificationEndpoint second returned error: %v", err)
	}
	if err := repo.CreateNotificationEndpoint(ctx, first); err != nil {
		t.Fatalf("CreateNotificationEndpoint first returned error: %v", err)
	}

	listed, err := repo.ListNotificationEndpoints(ctx)
	if err != nil {
		t.Fatalf("ListNotificationEndpoints returned error: %v", err)
	}
	if len(listed) != 2 || listed[0].ID != first.ID || listed[1].ID != second.ID {
		t.Fatalf("notification endpoints = %#v, want creation order", listed)
	}
	listed[0].EventTypes[0] = "mutated"
	stored, err := repo.GetNotificationEndpoint(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetNotificationEndpoint returned error: %v", err)
	}
	if stored.EventTypes[0] != "certificate.expiration_warning" {
		t.Fatalf("stored event types mutated through list: %#v", stored.EventTypes)
	}
	if stored.Secret != "secret-1" {
		t.Fatalf("stored secret = %q, want secret-1", stored.Secret)
	}

	stored.Status = domain.NotificationEndpointDisabled
	stored.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateNotificationEndpointIfStatus(ctx, stored, domain.NotificationEndpointActive); err != nil {
		t.Fatalf("UpdateNotificationEndpointIfStatus returned error: %v", err)
	}
	if err := repo.UpdateNotificationEndpointIfStatus(ctx, first, domain.NotificationEndpointActive); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateNotificationEndpointIfStatus error = %v, want ErrInvalidTransition", err)
	}
	disabled, err := repo.GetNotificationEndpoint(ctx, first.ID)
	if err != nil {
		t.Fatalf("GetNotificationEndpoint disabled returned error: %v", err)
	}
	if disabled.Status != domain.NotificationEndpointDisabled {
		t.Fatalf("disabled status = %q, want %q", disabled.Status, domain.NotificationEndpointDisabled)
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

func testAPIKeys(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(10, 0)
	key := domain.APIKey{
		ID:         "key-1",
		Name:       "admin",
		TokenHash:  "sha256:abc",
		Status:     domain.APIKeyActive,
		Actor:      "api-admin",
		Scopes:     []domain.APIKeyScope{domain.APIKeyScopeOperator},
		ExpiresAt:  now.Add(time.Hour),
		LastUsedAt: now.Add(time.Minute),
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := repo.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey returned error: %v", err)
	}
	got, err := repo.GetAPIKeyByTokenHash(ctx, key.TokenHash)
	if err != nil {
		t.Fatalf("GetAPIKeyByTokenHash returned error: %v", err)
	}
	if got.ID != key.ID || got.Actor != key.Actor || got.Status != key.Status ||
		len(got.Scopes) != 1 || got.Scopes[0] != domain.APIKeyScopeOperator ||
		!got.ExpiresAt.Equal(key.ExpiresAt) || !got.LastUsedAt.Equal(key.LastUsedAt) {
		t.Fatalf("api key = %#v, want %#v", got, key)
	}
	listed, err := repo.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("ListAPIKeys returned error: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != key.ID {
		t.Fatalf("api keys = %#v, want key-1", listed)
	}
	key.Status = domain.APIKeyDisabled
	key.LastUsedAt = now.Add(2 * time.Minute)
	key.UpdatedAt = now.Add(time.Second)
	if err := repo.UpdateAPIKeyIfStatus(ctx, key, domain.APIKeyActive); err != nil {
		t.Fatalf("UpdateAPIKeyIfStatus returned error: %v", err)
	}
	disabled, err := repo.GetAPIKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKey returned error: %v", err)
	}
	if disabled.Status != domain.APIKeyDisabled {
		t.Fatalf("api key status = %q, want disabled", disabled.Status)
	}
	if !disabled.LastUsedAt.Equal(key.LastUsedAt) {
		t.Fatalf("LastUsedAt = %s, want %s", disabled.LastUsedAt, key.LastUsedAt)
	}
	if _, err := repo.GetAPIKeyByTokenHash(ctx, "sha256:missing"); !errors.Is(err, domain.ErrAPIKeyNotFound) {
		t.Fatalf("GetAPIKeyByTokenHash missing error = %v, want ErrAPIKeyNotFound", err)
	}
}

func testIssuerTrustMetadata(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(10, 0)
	issuer := domain.Issuer{
		ID:                    "issuer-1",
		Name:                  "intermediate",
		Kind:                  domain.IssuerIntermediateCA,
		Status:                domain.IssuerActive,
		ParentIssuerID:        "root-1",
		CertificatePEM:        "issuer-pem",
		KeyRef:                "issuer-key",
		AIAURL:                "https://pki.example.test/issuers/intermediate.pem",
		CRLDistributionPoints: []string{"https://pki.example.test/crl/intermediate.pem"},
		TrustAnchor:           false,
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := repo.CreateIssuer(ctx, issuer); err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	got, err := repo.GetIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetIssuer returned error: %v", err)
	}
	if got.ParentIssuerID != issuer.ParentIssuerID ||
		got.AIAURL != issuer.AIAURL ||
		got.TrustAnchor != issuer.TrustAnchor ||
		len(got.CRLDistributionPoints) != 1 ||
		got.CRLDistributionPoints[0] != issuer.CRLDistributionPoints[0] {
		t.Fatalf("issuer metadata = %#v, want %#v", got, issuer)
	}
}

func testACMEState(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	account := domain.ACMEAccount{
		ID:                   "account-1",
		Contacts:             []string{"mailto:ops@example.test"},
		Status:               domain.ACMEAccountValid,
		TermsOfServiceAgreed: true,
		KeyThumbprint:        "thumbprint-1",
		KeyJWKJSON:           `{"crv":"P-256","kty":"EC","x":"x","y":"y"}`,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateACMEAccount(ctx, account); err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	gotAccount, err := repo.GetACMEAccount(ctx, account.ID)
	if err != nil {
		t.Fatalf("GetACMEAccount returned error: %v", err)
	}
	if gotAccount.Status != account.Status ||
		gotAccount.KeyThumbprint != account.KeyThumbprint ||
		gotAccount.KeyJWKJSON != account.KeyJWKJSON ||
		len(gotAccount.Contacts) != 1 ||
		gotAccount.Contacts[0] != account.Contacts[0] {
		t.Fatalf("account = %#v, want %#v", gotAccount, account)
	}

	order := domain.ACMEOrder{
		ID:                   "order-1",
		AccountID:            account.ID,
		IdentityID:           "identity-1",
		IssuerID:             "issuer-1",
		CertificateProfileID: "profile-1",
		Status:               domain.ACMEOrderPending,
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"192.0.2.10"},
		RequestedNotAfter:    now.Add(24 * time.Hour),
		ExpiresAt:            now.Add(2 * time.Hour),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := repo.CreateACMEOrder(ctx, order); err != nil {
		t.Fatalf("CreateACMEOrder returned error: %v", err)
	}
	order.Status = domain.ACMEOrderReady
	order.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); err != nil {
		t.Fatalf("UpdateACMEOrderIfStatus returned error: %v", err)
	}
	if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateACMEOrderIfStatus error = %v, want ErrInvalidTransition", err)
	}
	orders, err := repo.ListACMEOrdersByAccount(ctx, account.ID)
	if err != nil {
		t.Fatalf("ListACMEOrdersByAccount returned error: %v", err)
	}
	if len(orders) != 1 || orders[0].Status != domain.ACMEOrderReady || !orders[0].ExpiresAt.Equal(order.ExpiresAt) {
		t.Fatalf("orders = %#v", orders)
	}

	authz := domain.ACMEAuthorization{
		ID:              "authz-1",
		OrderID:         order.ID,
		IdentifierType:  "dns",
		IdentifierValue: "edge-01.example.test",
		Status:          domain.ACMEAuthorizationPending,
		ExpiresAt:       now.Add(2 * time.Hour),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := repo.CreateACMEAuthorization(ctx, authz); err != nil {
		t.Fatalf("CreateACMEAuthorization returned error: %v", err)
	}
	authz.Status = domain.ACMEAuthorizationValid
	authz.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEAuthorizationIfStatus(ctx, authz, domain.ACMEAuthorizationPending); err != nil {
		t.Fatalf("UpdateACMEAuthorizationIfStatus returned error: %v", err)
	}
	authzs, err := repo.ListACMEAuthorizationsByOrder(ctx, order.ID)
	if err != nil {
		t.Fatalf("ListACMEAuthorizationsByOrder returned error: %v", err)
	}
	if len(authzs) != 1 || authzs[0].Status != domain.ACMEAuthorizationValid || !authzs[0].ExpiresAt.Equal(authz.ExpiresAt) {
		t.Fatalf("authorizations = %#v", authzs)
	}

	challenge := domain.ACMEChallenge{
		ID:              "challenge-1",
		AuthorizationID: authz.ID,
		Type:            domain.ACMEChallengeHTTP01,
		Token:           "token-1",
		Status:          domain.ACMEChallengePending,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := repo.CreateACMEChallenge(ctx, challenge); err != nil {
		t.Fatalf("CreateACMEChallenge returned error: %v", err)
	}
	challenge.Status = domain.ACMEChallengeValid
	challenge.ValidatedAt = now.Add(time.Minute)
	challenge.UpdatedAt = now.Add(time.Minute)
	if err := repo.UpdateACMEChallengeIfStatus(ctx, challenge, domain.ACMEChallengePending); err != nil {
		t.Fatalf("UpdateACMEChallengeIfStatus returned error: %v", err)
	}
	challenges, err := repo.ListACMEChallengesByAuthorization(ctx, authz.ID)
	if err != nil {
		t.Fatalf("ListACMEChallengesByAuthorization returned error: %v", err)
	}
	if len(challenges) != 1 || challenges[0].Status != domain.ACMEChallengeValid || !challenges[0].ValidatedAt.Equal(challenge.ValidatedAt) {
		t.Fatalf("challenges = %#v", challenges)
	}
}

func testRejectsDuplicateACMEAccountThumbprint(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	account := domain.ACMEAccount{
		ID:            "account-1",
		Status:        domain.ACMEAccountValid,
		KeyThumbprint: "thumbprint-1",
		KeyJWKJSON:    `{"kty":"EC"}`,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := repo.CreateACMEAccount(ctx, account); err != nil {
		t.Fatalf("CreateACMEAccount returned error: %v", err)
	}
	account.ID = "account-2"
	if err := repo.CreateACMEAccount(ctx, account); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate CreateACMEAccount error = %v, want ErrInvalidTransition", err)
	}
}

func testRejectsDuplicateCRLPublicationNumber(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	publication := domain.CRLPublication{
		ID:                "crl-1",
		IssuerID:          "issuer-1",
		DistributionPoint: "https://pki.example.test/crl/issuer-1.pem",
		CRLNumber:         7,
		ThisUpdate:        now,
		NextUpdate:        now.Add(time.Hour),
		Status:            domain.CRLPublicationPublished,
		CRLPEM:            "crl-pem-1",
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := repo.CreateCRLPublication(ctx, publication); err != nil {
		t.Fatalf("CreateCRLPublication returned error: %v", err)
	}
	publication.ID = "crl-2"
	publication.CRLPEM = "crl-pem-2"
	if err := repo.CreateCRLPublication(ctx, publication); !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("duplicate CreateCRLPublication error = %v, want ErrInvalidTransition", err)
	}
}
