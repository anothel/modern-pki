package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modern-pki/modern-pki/service/internal/corecli"
	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

type CertificateIssuer interface {
	Issue(context.Context, corecli.IssueRequest) (corecli.IssueResult, error)
	InspectCSR(context.Context, string) (corecli.CSRInfo, error)
}

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewID() string
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

type UUIDGenerator struct{}

func (UUIDGenerator) NewID() string {
	return uuid.NewString()
}

type Service struct {
	repo   store.Repository
	issuer CertificateIssuer
	clock  Clock
	idgen  IDGenerator
}

type CreateIdentityRequest struct {
	Type       domain.IdentityType
	Name       string
	ExternalID string
}

type CreateIssuerRequest struct {
	Name           string
	Kind           domain.IssuerKind
	CertificatePEM string
	KeyRef         string
}

type CreateCertificateProfileRequest struct {
	Name                  string
	Description           string
	IssuerID              string
	ValidityPeriodSeconds int64
	SubjectTemplate       string
	AllowedDNSPatterns    []string
	AllowedIPRanges       []string
	KeyUsage              domain.StringListExtensionPolicy
	ExtendedKeyUsage      domain.StringListExtensionPolicy
	BasicConstraints      domain.BasicConstraintsPolicy
}

type CreateEnrollmentRequest struct {
	IdentityID           string
	IssuerID             string
	CSRPEM               string
	RequestedSubject     string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	RequestedNotAfter    time.Time
}

func New(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator) *Service {
	return &Service{
		repo:   repo,
		issuer: issuer,
		clock:  clock,
		idgen:  idgen,
	}
}

func (s *Service) CreateIdentity(ctx context.Context, actor string, req CreateIdentityRequest) (domain.Identity, error) {
	if err := validateCreateIdentityRequest(req); err != nil {
		return domain.Identity{}, err
	}

	now := s.clock.Now()
	identity := domain.Identity{
		ID:         s.idgen.NewID(),
		Type:       req.Type,
		Name:       req.Name,
		ExternalID: req.ExternalID,
		Status:     domain.IdentityActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateIdentity(ctx, identity); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "identity.created", "identity", identity.ID, now)
	}); err != nil {
		return domain.Identity{}, err
	}
	return identity, nil
}

func (s *Service) CreateIssuer(ctx context.Context, actor string, req CreateIssuerRequest) (domain.Issuer, error) {
	if err := validateCreateIssuerRequest(req); err != nil {
		return domain.Issuer{}, err
	}

	now := s.clock.Now()
	issuer := domain.Issuer{
		ID:             s.idgen.NewID(),
		Name:           req.Name,
		Kind:           req.Kind,
		Status:         domain.IssuerActive,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateIssuer(ctx, issuer); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "issuer.created", "issuer", issuer.ID, now)
	}); err != nil {
		return domain.Issuer{}, err
	}
	return issuer, nil
}

func (s *Service) CreateCertificateProfile(ctx context.Context, actor string, req CreateCertificateProfileRequest) (domain.CertificateProfile, error) {
	if err := validateCreateCertificateProfileRequest(req); err != nil {
		return domain.CertificateProfile{}, err
	}

	now := s.clock.Now()
	profile := domain.CertificateProfile{
		ID:                    s.idgen.NewID(),
		Name:                  req.Name,
		Description:           req.Description,
		IssuerID:              req.IssuerID,
		ValidityPeriodSeconds: req.ValidityPeriodSeconds,
		SubjectTemplate:       req.SubjectTemplate,
		AllowedDNSPatterns:    append([]string(nil), req.AllowedDNSPatterns...),
		AllowedIPRanges:       append([]string(nil), req.AllowedIPRanges...),
		KeyUsage:              copyStringListExtensionPolicy(req.KeyUsage),
		ExtendedKeyUsage:      copyStringListExtensionPolicy(req.ExtendedKeyUsage),
		BasicConstraints:      req.BasicConstraints,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		if err := repo.CreateCertificateProfile(ctx, profile); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "certificate_profile.created", "certificate_profile", profile.ID, now)
	}); err != nil {
		return domain.CertificateProfile{}, err
	}
	return profile, nil
}

func (s *Service) CreateEnrollment(ctx context.Context, actor string, req CreateEnrollmentRequest) (domain.Enrollment, error) {
	now := s.clock.Now()
	if err := validateCreateEnrollmentRequest(req, now); err != nil {
		return domain.Enrollment{}, err
	}

	if _, err := s.repo.GetIdentity(ctx, req.IdentityID); err != nil {
		return domain.Enrollment{}, err
	}
	if _, err := s.repo.GetIssuer(ctx, req.IssuerID); err != nil {
		return domain.Enrollment{}, err
	}

	csrInfo, err := s.issuer.InspectCSR(ctx, req.CSRPEM)
	if err != nil {
		return domain.Enrollment{}, mapCSRInspectError(err)
	}
	if !sameStringSet(req.RequestedDNSNames, csrInfo.DNSNames) || !sameStringSet(req.RequestedIPAddresses, csrInfo.IPAddresses) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}

	enrollment := domain.Enrollment{
		ID:                   s.idgen.NewID(),
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CSRPEM:               req.CSRPEM,
		Status:               domain.EnrollmentPending,
		RequestedSubject:     req.RequestedSubject,
		RequestedDNSNames:    append([]string(nil), req.RequestedDNSNames...),
		RequestedIPAddresses: append([]string(nil), req.RequestedIPAddresses...),
		CSRDNSNames:          append([]string(nil), csrInfo.DNSNames...),
		CSRIPAddresses:       append([]string(nil), csrInfo.IPAddresses...),
		RequestedNotAfter:    req.RequestedNotAfter,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIdentity(ctx, req.IdentityID); err != nil {
			return err
		}
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "enrollment.created", "enrollment", enrollment.ID, now)
	}); err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) ApproveEnrollment(ctx context.Context, actor string, id string) (domain.Enrollment, error) {
	if isBlank(id) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}

	var enrollment domain.Enrollment
	now := s.clock.Now()
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		var err error
		enrollment, err = repo.GetEnrollment(ctx, id)
		if err != nil {
			return err
		}
		if enrollment.Status != domain.EnrollmentPending {
			return domain.ErrInvalidTransition
		}

		enrollment.Status = domain.EnrollmentApproved
		enrollment.ApprovedBy = actor
		enrollment.ApprovedAt = now
		enrollment.UpdatedAt = now

		if err := repo.UpdateEnrollmentIfStatus(ctx, enrollment, domain.EnrollmentPending); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "enrollment.approved", "enrollment", enrollment.ID, now)
	}); err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) RejectEnrollment(ctx context.Context, actor string, id string) (domain.Enrollment, error) {
	if isBlank(id) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}

	var enrollment domain.Enrollment
	now := s.clock.Now()
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		var err error
		enrollment, err = repo.GetEnrollment(ctx, id)
		if err != nil {
			return err
		}
		if enrollment.Status != domain.EnrollmentPending {
			return domain.ErrInvalidTransition
		}

		enrollment.Status = domain.EnrollmentRejected
		enrollment.UpdatedAt = now

		if err := repo.UpdateEnrollmentIfStatus(ctx, enrollment, domain.EnrollmentPending); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "enrollment.rejected", "enrollment", enrollment.ID, now)
	}); err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) IssueCertificate(ctx context.Context, actor string, enrollmentID string) (domain.Certificate, error) {
	if isBlank(enrollmentID) {
		return domain.Certificate{}, domain.ErrInvalidRequest
	}

	enrollment, err := s.repo.GetEnrollment(ctx, enrollmentID)
	if err != nil {
		return domain.Certificate{}, err
	}
	if enrollment.Status != domain.EnrollmentApproved {
		return domain.Certificate{}, domain.ErrInvalidTransition
	}

	issuer, err := s.repo.GetIssuer(ctx, enrollment.IssuerID)
	if err != nil {
		return domain.Certificate{}, err
	}

	now := s.clock.Now()
	// MVP limit: signing precedes DB commit; conditional finalization below prevents stale issuers from persisting duplicates.
	result, err := s.issuer.Issue(ctx, corecli.IssueRequest{
		CSRPEM:               enrollment.CSRPEM,
		IssuerCertificatePEM: issuer.CertificatePEM,
		IssuerKeyRef:         issuer.KeyRef,
		Subject:              enrollment.RequestedSubject,
		DNSNames:             append([]string(nil), enrollment.RequestedDNSNames...),
		IPAddresses:          append([]string(nil), enrollment.RequestedIPAddresses...),
		NotBefore:            now,
		NotAfter:             enrollment.RequestedNotAfter,
		SignatureAlgorithm:   "ecdsa_with_sha256",
	})
	if err != nil {
		return domain.Certificate{}, mapIssueError(err)
	}

	var certificate domain.Certificate
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		currentEnrollment, err := repo.GetEnrollment(ctx, enrollmentID)
		if err != nil {
			return err
		}
		if currentEnrollment.Status != domain.EnrollmentApproved {
			return domain.ErrInvalidTransition
		}

		issuedEnrollment := currentEnrollment
		issuedEnrollment.Status = domain.EnrollmentIssued
		issuedEnrollment.UpdatedAt = now
		if err := repo.UpdateEnrollmentIfStatus(ctx, issuedEnrollment, domain.EnrollmentApproved); err != nil {
			return err
		}

		certificate = domain.Certificate{
			ID:             s.idgen.NewID(),
			IdentityID:     currentEnrollment.IdentityID,
			IssuerID:       currentEnrollment.IssuerID,
			EnrollmentID:   currentEnrollment.ID,
			SerialNumber:   result.SerialNumber,
			Subject:        result.Subject,
			DNSNames:       append([]string(nil), currentEnrollment.RequestedDNSNames...),
			IPAddresses:    append([]string(nil), currentEnrollment.RequestedIPAddresses...),
			NotBefore:      result.NotBefore,
			NotAfter:       result.NotAfter,
			Status:         domain.CertificateValid,
			CertificatePEM: result.CertificatePEM,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			return err
		}

		return s.createAuditEvent(ctx, repo, actor, "certificate.issued", "certificate", certificate.ID, now)
	}); err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) RevokeCertificate(ctx context.Context, actor string, certificateID string, reason domain.RevocationReason) (domain.Certificate, error) {
	if isBlank(certificateID) || !isValidRevocationReason(reason) {
		return domain.Certificate{}, domain.ErrInvalidRequest
	}

	var certificate domain.Certificate
	now := s.clock.Now()
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		var err error
		certificate, err = repo.GetCertificate(ctx, certificateID)
		if err != nil {
			return err
		}
		if certificate.Status != domain.CertificateValid {
			return domain.ErrInvalidTransition
		}

		certificate.Status = domain.CertificateRevoked
		certificate.UpdatedAt = now
		if err := repo.UpdateCertificateIfStatus(ctx, certificate, domain.CertificateValid); err != nil {
			return err
		}

		revocation := domain.Revocation{
			ID:            s.idgen.NewID(),
			CertificateID: certificate.ID,
			Reason:        reason,
			RevokedBy:     actor,
			RevokedAt:     now,
			CreatedAt:     now,
		}
		if err := repo.CreateRevocation(ctx, revocation); err != nil {
			return err
		}

		return s.createAuditEvent(ctx, repo, actor, "certificate.revoked", "certificate", certificate.ID, now)
	}); err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	return s.repo.ListIdentities(ctx)
}

func (s *Service) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	return s.repo.GetIdentity(ctx, id)
}

func (s *Service) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	return s.repo.ListCertificateProfiles(ctx)
}

func (s *Service) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	return s.repo.GetCertificateProfile(ctx, id)
}

func (s *Service) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	return s.repo.ListEnrollments(ctx)
}

func (s *Service) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	return s.repo.GetEnrollment(ctx, id)
}

func (s *Service) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	return s.repo.ListCertificates(ctx)
}

func (s *Service) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	return s.repo.GetCertificate(ctx, id)
}

func (s *Service) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repo.ListAuditEvents(ctx)
}

func (s *Service) createAuditEvent(ctx context.Context, repo store.Repository, actor string, action string, resourceType string, resourceID string, createdAt time.Time) error {
	return repo.CreateAuditEvent(ctx, domain.AuditEvent{
		ID:           s.idgen.NewID(),
		Actor:        actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		MetadataJSON: "{}",
		CreatedAt:    createdAt,
	})
}

func validateCreateIdentityRequest(req CreateIdentityRequest) error {
	if !isValidIdentityType(req.Type) || isBlank(req.Name) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func validateCreateIssuerRequest(req CreateIssuerRequest) error {
	if isBlank(req.Name) || !isValidIssuerKind(req.Kind) || isBlank(req.CertificatePEM) || isBlank(req.KeyRef) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func validateCreateCertificateProfileRequest(req CreateCertificateProfileRequest) error {
	if isBlank(req.Name) || isBlank(req.IssuerID) || req.ValidityPeriodSeconds <= 0 {
		return domain.ErrInvalidRequest
	}
	return nil
}

func validateCreateEnrollmentRequest(req CreateEnrollmentRequest, now time.Time) error {
	if isBlank(req.IdentityID) || isBlank(req.IssuerID) || isBlank(req.CSRPEM) || isBlank(req.RequestedSubject) {
		return domain.ErrInvalidRequest
	}
	if !req.RequestedNotAfter.After(now) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func isValidIdentityType(identityType domain.IdentityType) bool {
	switch identityType {
	case domain.IdentityUser,
		domain.IdentityMachine,
		domain.IdentityService,
		domain.IdentityIoTDevice,
		domain.IdentityWorkload:
		return true
	default:
		return false
	}
}

func isValidIssuerKind(kind domain.IssuerKind) bool {
	switch kind {
	case domain.IssuerRootCA, domain.IssuerIntermediateCA:
		return true
	default:
		return false
	}
}

func isValidRevocationReason(reason domain.RevocationReason) bool {
	switch reason {
	case domain.RevocationKeyCompromise,
		domain.RevocationCACompromise,
		domain.RevocationAffiliationChanged,
		domain.RevocationSuperseded,
		domain.RevocationCessationOfOperation,
		domain.RevocationPrivilegeWithdrawn,
		domain.RevocationUnspecified:
		return true
	default:
		return false
	}
}

func isBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func mapIssueError(err error) error {
	var commandErr *corecli.CommandError
	if errors.As(err, &commandErr) && commandErr.Code == "issue.csr_parse_failed" {
		return fmt.Errorf("%w: %w", domain.ErrCSRParseFailed, err)
	}
	return fmt.Errorf("%w: %w", domain.ErrCertificateIssuanceFailed, err)
}

func mapCSRInspectError(err error) error {
	return fmt.Errorf("%w: %w", domain.ErrCSRParseFailed, err)
}

func sameStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]string(nil), left...)
	rightCopy := append([]string(nil), right...)
	sort.Strings(leftCopy)
	sort.Strings(rightCopy)
	for i := range leftCopy {
		if leftCopy[i] != rightCopy[i] {
			return false
		}
	}
	return true
}

func copyStringListExtensionPolicy(policy domain.StringListExtensionPolicy) domain.StringListExtensionPolicy {
	policy.Values = append([]string(nil), policy.Values...)
	return policy
}
