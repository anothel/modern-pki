package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
)

func TestMemoryStoreWithinTxRollsBackOnError(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	errStop := errors.New("stop")

	err := repo.WithinTx(ctx, func(tx Repository) error {
		if err := tx.CreateIdentity(ctx, domain.Identity{
			ID:        "identity-1",
			Type:      domain.IdentityMachine,
			Name:      "edge-01",
			Status:    domain.IdentityActive,
			CreatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			UpdatedAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		}); err != nil {
			return err
		}
		return errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("WithinTx error = %v, want %v", err, errStop)
	}

	if _, err := repo.GetIdentity(ctx, "identity-1"); !errors.Is(err, domain.ErrIdentityNotFound) {
		t.Fatalf("GetIdentity error = %v, want ErrIdentityNotFound", err)
	}
}

func TestMemoryStoreNestedWithinTxUsesSameTransaction(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()

	err := repo.WithinTx(ctx, func(tx Repository) error {
		return tx.WithinTx(ctx, func(nested Repository) error {
			return nested.CreateAuditEvent(ctx, domain.AuditEvent{
				ID:           "audit-1",
				Actor:        "admin",
				Action:       "identity.created",
				ResourceType: "identity",
				ResourceID:   "identity-1",
				MetadataJSON: "{}",
				CreatedAt:    time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
			})
		})
	})
	if err != nil {
		t.Fatalf("WithinTx returned error: %v", err)
	}

	events, err := repo.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
}

func TestMemoryStoreUpdateEnrollmentIfStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	enrollment := domain.Enrollment{
		ID:                "enrollment-1",
		IdentityID:        "identity-1",
		IssuerID:          "issuer-1",
		CSRPEM:            "csr-pem",
		Status:            domain.EnrollmentPending,
		RequestedSubject:  "CN=edge-01",
		RequestedNotAfter: createdAt.Add(time.Hour),
		CreatedAt:         createdAt,
		UpdatedAt:         createdAt,
	}
	if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}

	approved := enrollment
	approved.Status = domain.EnrollmentApproved
	approved.UpdatedAt = createdAt.Add(time.Minute)
	if err := repo.UpdateEnrollmentIfStatus(ctx, approved, domain.EnrollmentPending); err != nil {
		t.Fatalf("UpdateEnrollmentIfStatus returned error: %v", err)
	}

	rejected := enrollment
	rejected.Status = domain.EnrollmentRejected
	rejected.UpdatedAt = createdAt.Add(2 * time.Minute)
	err := repo.UpdateEnrollmentIfStatus(ctx, rejected, domain.EnrollmentPending)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateEnrollmentIfStatus error = %v, want ErrInvalidTransition", err)
	}

	stored, err := repo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if stored.Status != domain.EnrollmentApproved {
		t.Fatalf("stored enrollment status = %q, want %q", stored.Status, domain.EnrollmentApproved)
	}
}

func TestMemoryStoreUpdateCertificateIfStatus(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStore()
	createdAt := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	certificate := domain.Certificate{
		ID:             "certificate-1",
		IdentityID:     "identity-1",
		IssuerID:       "issuer-1",
		EnrollmentID:   "enrollment-1",
		SerialNumber:   "01",
		Subject:        "CN=edge-01",
		NotBefore:      createdAt,
		NotAfter:       createdAt.Add(time.Hour),
		Status:         domain.CertificateValid,
		CertificatePEM: "cert-pem",
		CreatedAt:      createdAt,
		UpdatedAt:      createdAt,
	}
	if err := repo.CreateCertificate(ctx, certificate); err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	revoked := certificate
	revoked.Status = domain.CertificateRevoked
	revoked.UpdatedAt = createdAt.Add(time.Minute)
	if err := repo.UpdateCertificateIfStatus(ctx, revoked, domain.CertificateValid); err != nil {
		t.Fatalf("UpdateCertificateIfStatus returned error: %v", err)
	}

	validAgain := certificate
	validAgain.UpdatedAt = createdAt.Add(2 * time.Minute)
	err := repo.UpdateCertificateIfStatus(ctx, validAgain, domain.CertificateValid)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("stale UpdateCertificateIfStatus error = %v, want ErrInvalidTransition", err)
	}

	stored, err := repo.GetCertificate(ctx, certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if stored.Status != domain.CertificateRevoked {
		t.Fatalf("stored certificate status = %q, want %q", stored.Status, domain.CertificateRevoked)
	}
}

func TestMemoryStoreOCSPResponders(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
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
	if err := s.CreateIssuer(ctx, issuer); err != nil {
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
	if err := s.CreateOCSPResponder(ctx, first); err != nil {
		t.Fatalf("CreateOCSPResponder first returned error: %v", err)
	}
	if err := s.CreateOCSPResponder(ctx, second); err != nil {
		t.Fatalf("CreateOCSPResponder second returned error: %v", err)
	}
	active, err := s.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("GetActiveOCSPResponderByIssuer returned error: %v", err)
	}
	if active.ID != second.ID {
		t.Fatalf("active responder ID = %q, want %q", active.ID, second.ID)
	}
	list, err := s.ListOCSPRespondersByIssuer(ctx, issuer.ID)
	if err != nil {
		t.Fatalf("ListOCSPRespondersByIssuer returned error: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("responder count = %d, want 2", len(list))
	}
}
