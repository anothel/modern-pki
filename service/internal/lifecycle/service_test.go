package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/corecli"
	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

func TestManualEnrollmentLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	service := New(repo, issuerClient, clock, &fakeIDGenerator{})

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type:       domain.IdentityMachine,
		Name:       "edge-01",
		ExternalID: "asset-123",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	if identity.Status != domain.IdentityActive {
		t.Fatalf("identity status = %q, want %q", identity.Status, domain.IdentityActive)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	if issuer.Status != domain.IssuerActive {
		t.Fatalf("issuer status = %q, want %q", issuer.Status, domain.IssuerActive)
	}

	requestedNotAfter := clock.now.Add(24 * time.Hour)
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    requestedNotAfter,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if enrollment.Status != domain.EnrollmentPending {
		t.Fatalf("enrollment status = %q, want %q", enrollment.Status, domain.EnrollmentPending)
	}

	approved, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID)
	if err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	if approved.Status != domain.EnrollmentApproved {
		t.Fatalf("approved enrollment status = %q, want %q", approved.Status, domain.EnrollmentApproved)
	}
	if approved.ApprovedBy != "approver" {
		t.Fatalf("ApprovedBy = %q, want %q", approved.ApprovedBy, "approver")
	}

	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if certificate.Status != domain.CertificateValid {
		t.Fatalf("certificate status = %q, want %q", certificate.Status, domain.CertificateValid)
	}
	if certificate.Subject != "CN=edge-01" {
		t.Fatalf("certificate subject = %q, want %q", certificate.Subject, "CN=edge-01")
	}
	if certificate.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", certificate.CertificatePEM, "issued:csr-pem")
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	issueRequest := issuerClient.requests[0]
	if issueRequest.CSRPEM != "csr-pem" {
		t.Fatalf("Issue CSRPEM = %q, want %q", issueRequest.CSRPEM, "csr-pem")
	}
	if issueRequest.IssuerCertificatePEM != "issuer-cert-pem" {
		t.Fatalf("Issue IssuerCertificatePEM = %q, want %q", issueRequest.IssuerCertificatePEM, "issuer-cert-pem")
	}
	if issueRequest.IssuerKeyRef != "issuer-key-ref" {
		t.Fatalf("Issue IssuerKeyRef = %q, want %q", issueRequest.IssuerKeyRef, "issuer-key-ref")
	}
	if issueRequest.SignatureAlgorithm != "ecdsa_with_sha256" {
		t.Fatalf("Issue SignatureAlgorithm = %q, want %q", issueRequest.SignatureAlgorithm, "ecdsa_with_sha256")
	}

	issuedEnrollment, err := repo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if issuedEnrollment.Status != domain.EnrollmentIssued {
		t.Fatalf("issued enrollment status = %q, want %q", issuedEnrollment.Status, domain.EnrollmentIssued)
	}

	revoked, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationKeyCompromise)
	if err != nil {
		t.Fatalf("RevokeCertificate returned error: %v", err)
	}
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}

	rejectedEnrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "rejected-csr-pem",
		RequestedSubject:     "CN=rejected",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    requestedNotAfter,
	})
	if err != nil {
		t.Fatalf("CreateEnrollment for rejection returned error: %v", err)
	}
	rejected, err := service.RejectEnrollment(ctx, "operator", rejectedEnrollment.ID)
	if err != nil {
		t.Fatalf("RejectEnrollment returned error: %v", err)
	}
	if rejected.Status != domain.EnrollmentRejected {
		t.Fatalf("rejected enrollment status = %q, want %q", rejected.Status, domain.EnrollmentRejected)
	}

	events, err := service.ListAuditEvents(ctx)
	if err != nil {
		t.Fatalf("ListAuditEvents returned error: %v", err)
	}
	wantActions := []string{
		"identity.created",
		"issuer.created",
		"enrollment.created",
		"enrollment.approved",
		"certificate.issued",
		"certificate.revoked",
		"enrollment.created",
		"enrollment.rejected",
	}
	if len(events) != len(wantActions) {
		t.Fatalf("audit event count = %d, want %d", len(events), len(wantActions))
	}
	for i, want := range wantActions {
		if events[i].Action != want {
			t.Fatalf("audit event %d action = %q, want %q", i, events[i].Action, want)
		}
		if events[i].MetadataJSON != "{}" {
			t.Fatalf("audit event %d metadata = %q, want {}", i, events[i].MetadataJSON)
		}
	}
}

func TestIssueRequiresApprovedEnrollment(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidTransition", err)
	}
	if len(issuerClient.requests) != 0 {
		t.Fatalf("issuer request count = %d, want 0", len(issuerClient.requests))
	}
}

func TestIssueCertificateUsesEnrollmentProfile(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		KeyUsage: domain.StringListExtensionPolicy{
			Critical: true,
			Values:   []string{"digital_signature", "key_encipherment"},
		},
		ExtendedKeyUsage: domain.StringListExtensionPolicy{
			Values: []string{"server_auth"},
		},
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical: true,
			CA:       false,
		},
		SubjectKeyIdentifier:   true,
		AuthorityKeyIdentifier: true,
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err = service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	req := issuerClient.requests[0]
	if req.ProfileID != profile.ID {
		t.Fatalf("IssueRequest ProfileID = %q, want %q", req.ProfileID, profile.ID)
	}
	if !req.BasicConstraintsCritical || req.BasicConstraintsCA {
		t.Fatalf("IssueRequest basic constraints = critical:%t ca:%t", req.BasicConstraintsCritical, req.BasicConstraintsCA)
	}
	if !req.KeyUsageCritical || !reflect.DeepEqual(req.KeyUsage, []string{"digital_signature", "key_encipherment"}) {
		t.Fatalf("IssueRequest key usage = critical:%t values:%#v", req.KeyUsageCritical, req.KeyUsage)
	}
	if !reflect.DeepEqual(req.ExtendedKeyUsage, []string{"server_auth"}) {
		t.Fatalf("IssueRequest extended key usage = %#v", req.ExtendedKeyUsage)
	}
	if !req.SubjectKeyIdentifier || !req.AuthorityKeyIdentifier {
		t.Fatalf("IssueRequest key identifiers = ski:%t aki:%t", req.SubjectKeyIdentifier, req.AuthorityKeyIdentifier)
	}
}

func TestIssueCertificatePreservesZeroProfilePathLen(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{csrInfo: corecli.CSRInfo{
		Subject:     "CN=edge-ca",
		DNSNames:    []string{"edge-ca.example.test"},
		IPAddresses: []string{"127.0.0.1"},
	}}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-ca",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "root-ca",
		Kind:           domain.IssuerRootCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	maxPathLen := 0
	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "intermediate-ca",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical:   true,
			CA:         true,
			MaxPathLen: &maxPathLen,
		},
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}
	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CertificateProfileID: profile.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-ca",
		RequestedDNSNames:    []string{"edge-ca.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	if _, err := service.IssueCertificate(ctx, "issuer", enrollment.ID); err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	if len(issuerClient.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(issuerClient.requests))
	}
	got := issuerClient.requests[0].BasicConstraintsMaxPathLen
	if got == nil || *got != 0 {
		t.Fatalf("IssueRequest BasicConstraintsMaxPathLen = %#v, want pointer to 0", got)
	}
}

func TestCreateIdentityRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name string
		req  CreateIdentityRequest
	}{
		{
			name: "invalid type",
			req: CreateIdentityRequest{
				Type: domain.IdentityType("device"),
				Name: "edge-01",
			},
		},
		{
			name: "empty name",
			req: CreateIdentityRequest{
				Type: domain.IdentityMachine,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{},
				fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
				&fakeIDGenerator{},
			)

			_, err := service.CreateIdentity(ctx, "admin", tt.req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateIdentity error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateIssuerRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	valid := CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	}
	tests := []struct {
		name   string
		mutate func(*CreateIssuerRequest)
	}{
		{name: "empty name", mutate: func(req *CreateIssuerRequest) { req.Name = "" }},
		{name: "invalid kind", mutate: func(req *CreateIssuerRequest) { req.Kind = domain.IssuerKind("leaf") }},
		{name: "empty certificate", mutate: func(req *CreateIssuerRequest) { req.CertificatePEM = "" }},
		{name: "empty key ref", mutate: func(req *CreateIssuerRequest) { req.KeyRef = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := valid
			tt.mutate(&req)
			service := New(
				store.NewMemoryStore(),
				&fakeIssuer{},
				fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
				&fakeIDGenerator{},
			)

			_, err := service.CreateIssuer(ctx, "admin", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateIssuer error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateCertificateProfile(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	profile, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		Description:           "Machine TLS server profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64((24 * time.Hour).Seconds()),
		SubjectTemplate:       "CN={{identity.name}}",
		AllowedDNSPatterns:    []string{"*.example.test"},
		KeyUsage: domain.StringListExtensionPolicy{
			Critical: true,
			Values:   []string{"digital_signature", "key_encipherment"},
		},
		ExtendedKeyUsage: domain.StringListExtensionPolicy{
			Critical: false,
			Values:   []string{"server_auth"},
		},
		BasicConstraints: domain.BasicConstraintsPolicy{
			Critical: true,
			CA:       false,
		},
	})
	if err != nil {
		t.Fatalf("CreateCertificateProfile returned error: %v", err)
	}

	if profile.Name != "machine-server" {
		t.Fatalf("profile name = %q, want machine-server", profile.Name)
	}
	if profile.IssuerID != issuer.ID {
		t.Fatalf("profile issuer ID = %q, want %q", profile.IssuerID, issuer.ID)
	}
	if !profile.KeyUsage.Critical || !reflect.DeepEqual(profile.KeyUsage.Values, []string{"digital_signature", "key_encipherment"}) {
		t.Fatalf("profile key usage = %#v", profile.KeyUsage)
	}

	got, err := service.GetCertificateProfile(ctx, profile.ID)
	if err != nil {
		t.Fatalf("GetCertificateProfile returned error: %v", err)
	}
	if got.ID != profile.ID {
		t.Fatalf("got profile ID = %q, want %q", got.ID, profile.ID)
	}

	profiles, err := service.ListCertificateProfiles(ctx)
	if err != nil {
		t.Fatalf("ListCertificateProfiles returned error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("profile count = %d, want 1", len(profiles))
	}
}

func TestCreateCertificateProfileRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})

	_, err := service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "machine-server",
		IssuerID:              "missing-issuer",
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
	})
	if !errors.Is(err, domain.ErrIssuerNotFound) {
		t.Fatalf("missing issuer error = %v, want ErrIssuerNotFound", err)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("invalid profile error = %v, want ErrInvalidRequest", err)
	}

	negativePathLen := -1
	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-ca-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA:         true,
			MaxPathLen: &negativePathLen,
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("negative max path len error = %v, want ErrInvalidRequest", err)
	}

	zeroPathLen := 0
	_, err = service.CreateCertificateProfile(ctx, "admin", CreateCertificateProfileRequest{
		Name:                  "bad-leaf-profile",
		IssuerID:              issuer.ID,
		ValidityPeriodSeconds: int64(time.Hour.Seconds()),
		BasicConstraints: domain.BasicConstraintsPolicy{
			CA:         false,
			MaxPathLen: &zeroPathLen,
		},
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("leaf max path len error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateEnrollmentRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*CreateEnrollmentRequest)
	}{
		{name: "empty identity", mutate: func(req *CreateEnrollmentRequest) { req.IdentityID = "" }},
		{name: "empty issuer", mutate: func(req *CreateEnrollmentRequest) { req.IssuerID = "" }},
		{name: "empty csr", mutate: func(req *CreateEnrollmentRequest) { req.CSRPEM = "" }},
		{name: "empty subject", mutate: func(req *CreateEnrollmentRequest) { req.RequestedSubject = "" }},
		{name: "not after is not future", mutate: func(req *CreateEnrollmentRequest) { req.RequestedNotAfter = now }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := New(store.NewMemoryStore(), &fakeIssuer{}, fixedClock{now: now}, &fakeIDGenerator{})
			identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
				Type: domain.IdentityMachine,
				Name: "edge-01",
			})
			if err != nil {
				t.Fatalf("CreateIdentity returned error: %v", err)
			}
			issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
				Name:           "intermediate-ca",
				Kind:           domain.IssuerIntermediateCA,
				CertificatePEM: "issuer-cert-pem",
				KeyRef:         "issuer-key-ref",
			})
			if err != nil {
				t.Fatalf("CreateIssuer returned error: %v", err)
			}

			req := CreateEnrollmentRequest{
				IdentityID:        identity.ID,
				IssuerID:          issuer.ID,
				CSRPEM:            "csr-pem",
				RequestedSubject:  "CN=edge-01",
				RequestedNotAfter: now.Add(time.Hour),
			}
			tt.mutate(&req)

			_, err = service.CreateEnrollment(ctx, "operator", req)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestCreateEnrollmentStoresCSRSANs(t *testing.T) {
	ctx := context.Background()
	coreClient := &fakeIssuer{
		csrInfo: corecli.CSRInfo{
			Subject:     "CN=edge-01",
			DNSNames:    []string{"edge-01.example.test", "edge-01.internal.test"},
			IPAddresses: []string{"127.0.0.1"},
		},
	}
	service := New(
		store.NewMemoryStore(),
		coreClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.internal.test", "edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}

	if !reflect.DeepEqual(enrollment.CSRDNSNames, coreClient.csrInfo.DNSNames) {
		t.Fatalf("CSRDNSNames = %#v, want %#v", enrollment.CSRDNSNames, coreClient.csrInfo.DNSNames)
	}
	if !reflect.DeepEqual(enrollment.CSRIPAddresses, coreClient.csrInfo.IPAddresses) {
		t.Fatalf("CSRIPAddresses = %#v, want %#v", enrollment.CSRIPAddresses, coreClient.csrInfo.IPAddresses)
	}
}

func TestCreateEnrollmentRejectsSANMismatch(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{
			csrInfo: corecli.CSRInfo{
				Subject:     "CN=edge-01",
				DNSNames:    []string{"csr.example.test"},
				IPAddresses: []string{"127.0.0.1"},
			},
		},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)
	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	_, err = service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"request.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if !errors.Is(err, domain.ErrInvalidRequest) {
		t.Fatalf("CreateEnrollment error = %v, want ErrInvalidRequest", err)
	}
}

func TestIssueCertificateMapsCSRParseFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	issuerClient := &fakeIssuer{
		err: &corecli.CommandError{
			Code:    "issue.csr_parse_failed",
			Message: "bad csr",
			Err:     errors.New("exit status 1"),
		},
	}
	service := New(
		repo,
		issuerClient,
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrCSRParseFailed) {
		t.Fatalf("IssueCertificate error = %v, want ErrCSRParseFailed", err)
	}
	if errors.Is(err, domain.ErrCertificateIssuanceFailed) {
		t.Fatalf("IssueCertificate error = %v, did not want ErrCertificateIssuanceFailed", err)
	}
}

func TestIssueCertificateDoesNotCreateCertificateAfterStaleTransition(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	staleRepo := &staleTransitionRepository{Repository: repo}
	service := New(
		staleRepo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	staleRepo.failConditionalUpdate = true

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("IssueCertificate error = %v, want ErrInvalidTransition", err)
	}
	if staleRepo.createCertificateCalled {
		t.Fatal("CreateCertificate called after stale enrollment transition")
	}
}

func TestRevokeCertificateRejectsInvalidRequest(t *testing.T) {
	ctx := context.Background()
	service := New(
		store.NewMemoryStore(),
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	tests := []struct {
		name          string
		certificateID string
		reason        domain.RevocationReason
	}{
		{name: "empty certificate", certificateID: "", reason: domain.RevocationSuperseded},
		{name: "invalid reason", certificateID: "certificate-1", reason: domain.RevocationReason("bad")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.RevokeCertificate(ctx, "operator", tt.certificateID, tt.reason)
			if !errors.Is(err, domain.ErrInvalidRequest) {
				t.Fatalf("RevokeCertificate error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestRevokeCertificateDoesNotCreateRevocationAfterStaleTransition(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	staleRepo := &staleRevocationRepository{Repository: repo}
	service := New(
		staleRepo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	staleRepo.failConditionalUpdate = true

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("RevokeCertificate error = %v, want ErrInvalidTransition", err)
	}
	if staleRepo.createRevocationCalled {
		t.Fatal("CreateRevocation called after stale certificate transition")
	}
}

func TestOnlyValidCertificateCanBeRevoked(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	service := New(
		repo,
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	if _, err := service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded); err != nil {
		t.Fatalf("first RevokeCertificate returned error: %v", err)
	}

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, domain.ErrInvalidTransition) {
		t.Fatalf("second RevokeCertificate error = %v, want ErrInvalidTransition", err)
	}
}

func TestIssueCertificateRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	errAudit := errors.New("audit failed")
	service := New(
		&failAuditRepository{Repository: repo, action: "certificate.issued", err: errAudit},
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}

	_, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if !errors.Is(err, errAudit) {
		t.Fatalf("IssueCertificate error = %v, want audit error", err)
	}

	certificates, err := repo.ListCertificates(ctx)
	if err != nil {
		t.Fatalf("ListCertificates returned error: %v", err)
	}
	if len(certificates) != 0 {
		t.Fatalf("certificate count = %d, want 0", len(certificates))
	}
	storedEnrollment, err := repo.GetEnrollment(ctx, enrollment.ID)
	if err != nil {
		t.Fatalf("GetEnrollment returned error: %v", err)
	}
	if storedEnrollment.Status != domain.EnrollmentApproved {
		t.Fatalf("enrollment status = %q, want %q", storedEnrollment.Status, domain.EnrollmentApproved)
	}
}

func TestRevokeCertificateRollsBackWhenAuditFails(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	errAudit := errors.New("audit failed")
	service := New(
		&failAuditRepository{Repository: repo, action: "certificate.revoked", err: errAudit},
		&fakeIssuer{},
		fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)},
		&fakeIDGenerator{},
	)

	enrollment := createPendingEnrollment(t, ctx, service)
	if _, err := service.ApproveEnrollment(ctx, "approver", enrollment.ID); err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	certificate, err := service.IssueCertificate(ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}

	_, err = service.RevokeCertificate(ctx, "operator", certificate.ID, domain.RevocationSuperseded)
	if !errors.Is(err, errAudit) {
		t.Fatalf("RevokeCertificate error = %v, want audit error", err)
	}

	storedCertificate, err := repo.GetCertificate(ctx, certificate.ID)
	if err != nil {
		t.Fatalf("GetCertificate returned error: %v", err)
	}
	if storedCertificate.Status != domain.CertificateValid {
		t.Fatalf("certificate status = %q, want %q", storedCertificate.Status, domain.CertificateValid)
	}
}

func createPendingEnrollment(t *testing.T, ctx context.Context, service *Service) domain.Enrollment {
	t.Helper()

	identity, err := service.CreateIdentity(ctx, "admin", CreateIdentityRequest{
		Type: domain.IdentityMachine,
		Name: "edge-01",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}

	issuer, err := service.CreateIssuer(ctx, "admin", CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}

	enrollment, err := service.CreateEnrollment(ctx, "operator", CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    time.Date(2026, time.January, 3, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	return enrollment
}

type fakeIssuer struct {
	requests []corecli.IssueRequest
	csrInfo  corecli.CSRInfo
	err      error
}

func (f *fakeIssuer) InspectCSR(ctx context.Context, csrPEM string) (corecli.CSRInfo, error) {
	if f.csrInfo.Subject != "" || len(f.csrInfo.DNSNames) != 0 || len(f.csrInfo.IPAddresses) != 0 {
		return f.csrInfo, nil
	}
	return corecli.CSRInfo{
		Subject:     "CN=edge-01",
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []string{"127.0.0.1"},
	}, nil
}

func (f *fakeIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return corecli.IssueResult{}, f.err
	}
	return corecli.IssueResult{
		CertificatePEM: "issued:" + req.CSRPEM,
		SerialNumber:   "serial:" + req.Subject,
		Subject:        req.Subject,
		NotBefore:      req.NotBefore,
		NotAfter:       req.NotAfter,
	}, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type fakeIDGenerator struct {
	next int
}

func (g *fakeIDGenerator) NewID() string {
	g.next++
	return fmt.Sprintf("id-%d", g.next)
}

type failAuditRepository struct {
	store.Repository
	action string
	err    error
}

func (r *failAuditRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&failAuditRepository{
			Repository: tx,
			action:     r.action,
			err:        r.err,
		})
	})
}

func (r *failAuditRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	if event.Action == r.action {
		return r.err
	}
	return r.Repository.CreateAuditEvent(ctx, event)
}

type staleTransitionRepository struct {
	store.Repository
	createCertificateCalled bool
	failConditionalUpdate   bool
}

func (r *staleTransitionRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&staleTransitionTx{
			Repository: tx,
			parent:     r,
		})
	})
}

type staleTransitionTx struct {
	store.Repository
	parent *staleTransitionRepository
}

func (tx *staleTransitionTx) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	if tx.parent.failConditionalUpdate {
		return domain.ErrInvalidTransition
	}
	return tx.Repository.UpdateEnrollmentIfStatus(ctx, enrollment, currentStatus)
}

func (tx *staleTransitionTx) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	tx.parent.createCertificateCalled = true
	return errors.New("CreateCertificate should not be called")
}

type staleRevocationRepository struct {
	store.Repository
	createRevocationCalled bool
	failConditionalUpdate  bool
}

func (r *staleRevocationRepository) WithinTx(ctx context.Context, fn func(store.Repository) error) error {
	return r.Repository.WithinTx(ctx, func(tx store.Repository) error {
		return fn(&staleRevocationTx{
			Repository: tx,
			parent:     r,
		})
	})
}

type staleRevocationTx struct {
	store.Repository
	parent *staleRevocationRepository
}

func (tx *staleRevocationTx) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	if tx.parent.failConditionalUpdate {
		return domain.ErrInvalidTransition
	}
	return tx.Repository.UpdateCertificateIfStatus(ctx, certificate, currentStatus)
}

func (tx *staleRevocationTx) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	tx.parent.createRevocationCalled = true
	return errors.New("CreateRevocation should not be called")
}
