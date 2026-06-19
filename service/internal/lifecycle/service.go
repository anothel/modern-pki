package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
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
	GenerateCRL(context.Context, corecli.GenerateCRLRequest) (corecli.GenerateCRLResult, error)
	InspectOCSPIssuer(context.Context, string, string) (corecli.OCSPIssuerInfo, error)
	ValidateOCSPResponder(context.Context, string, string) (corecli.ValidateOCSPResponderResult, error)
	InspectOCSP(context.Context, []byte) (corecli.OCSPRequestInfo, error)
	GenerateOCSPResponse(context.Context, corecli.GenerateOCSPResponseRequest) (corecli.GenerateOCSPResponseResult, error)
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

type AuditRequestMetadata struct {
	RequestID string
	ClientIP  string
	StartedAt time.Time
}

type APIFailureAuditRequest struct {
	Method     string
	Path       string
	StatusCode int
	Err        error
}

type auditRequestMetadataContextKey struct{}

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

type CreateOCSPResponderRequest struct {
	IssuerID       string
	Name           string
	CertificatePEM string
	KeyRef         string
}

type RotateOCSPResponderRequest struct {
	IssuerID       string
	Name           string
	CertificatePEM string
	KeyRef         string
}

type CreateNotificationEndpointRequest struct {
	Name       string
	URL        string
	EventTypes []string
}

type CreateCertificateProfileRequest struct {
	Name                   string
	Description            string
	IssuerID               string
	ValidityPeriodSeconds  int64
	SubjectTemplate        string
	AllowedDNSPatterns     []string
	AllowedIPRanges        []string
	KeyUsage               domain.StringListExtensionPolicy
	ExtendedKeyUsage       domain.StringListExtensionPolicy
	BasicConstraints       domain.BasicConstraintsPolicy
	SubjectKeyIdentifier   bool
	AuthorityKeyIdentifier bool
}

type CreateEnrollmentRequest struct {
	IdentityID           string
	IssuerID             string
	CertificateProfileID string
	CSRPEM               string
	RequestedSubject     string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	RequestedNotAfter    time.Time
}

type RenewCertificateRequest struct {
	CSRPEM            string
	RequestedNotAfter time.Time
}

type ReissueCertificateRequest struct {
	CSRPEM string
}

type ScanCertificateExpirationsRequest struct {
	WarningWindow time.Duration
	Limit         int
}

type CertificateExpirationScanResult struct {
	Expired            []domain.Certificate
	ExpirationWarnings []domain.Certificate
}

type PublishCRLRequest struct {
	IssuerID          string
	DistributionPoint string
	NextUpdate        time.Time
}

type OCSPResponse struct {
	ResponseDER []byte
}

type ocspSigner struct {
	CertificatePEM string
	KeyRef         string
	ResponderMode  string
	ResponderID    string
}

func New(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator) *Service {
	return &Service{
		repo:   repo,
		issuer: issuer,
		clock:  clock,
		idgen:  idgen,
	}
}

func WithAuditRequestMetadata(ctx context.Context, metadata AuditRequestMetadata) context.Context {
	return context.WithValue(ctx, auditRequestMetadataContextKey{}, metadata)
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
		return s.createAuditEvent(ctx, repo, actor, "identity.created", "identity", identity.ID, now, auditFields(
			"identity_id", identity.ID,
		))
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
		return s.createAuditEvent(ctx, repo, actor, "issuer.created", "issuer", issuer.ID, now, auditFields(
			"issuer_id", issuer.ID,
		))
	}); err != nil {
		return domain.Issuer{}, err
	}
	return issuer, nil
}

func (s *Service) CreateOCSPResponder(ctx context.Context, actor string, req CreateOCSPResponderRequest) (domain.OCSPResponder, error) {
	if isBlank(req.IssuerID) || isBlank(req.Name) || isBlank(req.CertificatePEM) || isBlank(req.KeyRef) {
		return domain.OCSPResponder{}, domain.ErrInvalidRequest
	}

	now := s.clock.Now()
	issuer, err := s.repo.GetIssuer(ctx, req.IssuerID)
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	if _, err := s.repo.GetActiveOCSPResponderByIssuer(ctx, req.IssuerID); err == nil {
		return domain.OCSPResponder{}, domain.ErrInvalidTransition
	} else if !errors.Is(err, domain.ErrOCSPResponderNotFound) {
		return domain.OCSPResponder{}, err
	}
	validation, err := s.issuer.ValidateOCSPResponder(ctx, issuer.CertificatePEM, req.CertificatePEM)
	if err != nil {
		return domain.OCSPResponder{}, mapOCSPResponseError(err)
	}
	if !validation.Valid {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderValidationFailed
	}

	responder := domain.OCSPResponder{
		ID:             s.idgen.NewID(),
		IssuerID:       req.IssuerID,
		Name:           req.Name,
		Status:         domain.OCSPResponderActive,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateOCSPResponder(ctx, responder); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "ocsp_responder.created", "ocsp_responder", responder.ID, now, auditFields(
			"issuer_id", responder.IssuerID,
			"ocsp_responder_id", responder.ID,
		))
	}); err != nil {
		return domain.OCSPResponder{}, err
	}

	return responder, nil
}

func (s *Service) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	if isBlank(issuerID) {
		return nil, domain.ErrInvalidRequest
	}
	if _, err := s.repo.GetIssuer(ctx, issuerID); err != nil {
		return nil, err
	}
	return s.repo.ListOCSPRespondersByIssuer(ctx, issuerID)
}

func (s *Service) DisableOCSPResponder(ctx context.Context, actor string, issuerID string, responderID string) (domain.OCSPResponder, error) {
	if isBlank(issuerID) || isBlank(responderID) {
		return domain.OCSPResponder{}, domain.ErrInvalidRequest
	}

	var responder domain.OCSPResponder
	now := s.clock.Now()
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIssuer(ctx, issuerID); err != nil {
			return err
		}
		var err error
		responder, err = repo.GetOCSPResponder(ctx, responderID)
		if err != nil {
			return err
		}
		if responder.IssuerID != issuerID {
			return domain.ErrOCSPResponderNotFound
		}
		if responder.Status != domain.OCSPResponderActive {
			return domain.ErrInvalidTransition
		}
		responder.Status = domain.OCSPResponderDisabled
		responder.UpdatedAt = now
		if err := repo.UpdateOCSPResponderIfStatus(ctx, responder, domain.OCSPResponderActive); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "ocsp_responder.disabled", "ocsp_responder", responder.ID, now, auditFields(
			"issuer_id", responder.IssuerID,
			"ocsp_responder_id", responder.ID,
		))
	}); err != nil {
		return domain.OCSPResponder{}, err
	}
	return responder, nil
}

func (s *Service) RotateOCSPResponder(ctx context.Context, actor string, req RotateOCSPResponderRequest) (domain.OCSPResponder, error) {
	if isBlank(req.IssuerID) || isBlank(req.Name) || isBlank(req.CertificatePEM) || isBlank(req.KeyRef) {
		return domain.OCSPResponder{}, domain.ErrInvalidRequest
	}

	now := s.clock.Now()
	issuer, err := s.repo.GetIssuer(ctx, req.IssuerID)
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	if _, err := s.repo.GetActiveOCSPResponderByIssuer(ctx, req.IssuerID); errors.Is(err, domain.ErrOCSPResponderNotFound) {
		return domain.OCSPResponder{}, domain.ErrInvalidTransition
	} else if err != nil {
		return domain.OCSPResponder{}, err
	}
	validation, err := s.issuer.ValidateOCSPResponder(ctx, issuer.CertificatePEM, req.CertificatePEM)
	if err != nil {
		return domain.OCSPResponder{}, mapOCSPResponseError(err)
	}
	if !validation.Valid {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderValidationFailed
	}

	responder := domain.OCSPResponder{
		ID:             s.idgen.NewID(),
		IssuerID:       req.IssuerID,
		Name:           req.Name,
		Status:         domain.OCSPResponderActive,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		current, err := repo.GetActiveOCSPResponderByIssuer(ctx, req.IssuerID)
		if errors.Is(err, domain.ErrOCSPResponderNotFound) {
			return domain.ErrInvalidTransition
		}
		if err != nil {
			return err
		}
		current.Status = domain.OCSPResponderDisabled
		current.UpdatedAt = now
		if err := repo.UpdateOCSPResponderIfStatus(ctx, current, domain.OCSPResponderActive); err != nil {
			return err
		}
		if err := s.createAuditEvent(ctx, repo, actor, "ocsp_responder.disabled", "ocsp_responder", current.ID, now, auditFields(
			"issuer_id", current.IssuerID,
			"ocsp_responder_id", current.ID,
		)); err != nil {
			return err
		}
		if err := repo.CreateOCSPResponder(ctx, responder); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "ocsp_responder.created", "ocsp_responder", responder.ID, now, auditFields(
			"issuer_id", responder.IssuerID,
			"ocsp_responder_id", responder.ID,
		))
	}); err != nil {
		return domain.OCSPResponder{}, err
	}

	return responder, nil
}

func (s *Service) CreateNotificationEndpoint(ctx context.Context, actor string, req CreateNotificationEndpointRequest) (domain.NotificationEndpoint, error) {
	if err := validateCreateNotificationEndpointRequest(req); err != nil {
		return domain.NotificationEndpoint{}, err
	}

	now := s.clock.Now()
	endpoint := domain.NotificationEndpoint{
		ID:         s.idgen.NewID(),
		Name:       req.Name,
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        req.URL,
		EventTypes: append([]string(nil), req.EventTypes...),
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateNotificationEndpoint(ctx, endpoint); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "notification_endpoint.created", "notification_endpoint", endpoint.ID, now, auditFields(
			"notification_endpoint_id", endpoint.ID,
			"notification_endpoint_type", string(endpoint.Type),
		))
	}); err != nil {
		return domain.NotificationEndpoint{}, err
	}
	return endpoint, nil
}

func (s *Service) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	return s.repo.ListNotificationEndpoints(ctx)
}

func (s *Service) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	if status != "" && !isValidOutboxMessageStatus(status) {
		return nil, domain.ErrInvalidRequest
	}
	return s.repo.ListOutboxMessages(ctx, status)
}

func (s *Service) RetryOutboxMessage(ctx context.Context, actor string, id string) (domain.OutboxMessage, error) {
	if isBlank(id) {
		return domain.OutboxMessage{}, domain.ErrInvalidRequest
	}

	now := s.clock.Now()
	message, err := s.repo.GetOutboxMessage(ctx, id)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	currentStatus := message.Status
	if currentStatus != domain.OutboxDeadLetter && currentStatus != domain.OutboxFailed {
		return domain.OutboxMessage{}, domain.ErrInvalidTransition
	}
	message.Status = domain.OutboxPending
	message.AvailableAt = now
	message.AttemptCount = 0
	if message.MaxAttempts <= 0 {
		message.MaxAttempts = defaultOutboxMaxAttempts
	}
	message.LastError = ""
	message.UpdatedAt = now

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, message, currentStatus); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "outbox.retry_requested", "outbox_message", message.ID, now, auditFields(
			"outbox_message_id", message.ID,
			"outbox_message_type", message.Type,
		))
	}); err != nil {
		return domain.OutboxMessage{}, err
	}
	return message, nil
}

func (s *Service) DisableNotificationEndpoint(ctx context.Context, actor string, id string) (domain.NotificationEndpoint, error) {
	if isBlank(id) {
		return domain.NotificationEndpoint{}, domain.ErrInvalidRequest
	}

	now := s.clock.Now()
	endpoint, err := s.repo.GetNotificationEndpoint(ctx, id)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	if endpoint.Status != domain.NotificationEndpointActive {
		return domain.NotificationEndpoint{}, domain.ErrInvalidTransition
	}
	endpoint.Status = domain.NotificationEndpointDisabled
	endpoint.UpdatedAt = now

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.UpdateNotificationEndpointIfStatus(ctx, endpoint, domain.NotificationEndpointActive); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "notification_endpoint.disabled", "notification_endpoint", endpoint.ID, now, auditFields(
			"notification_endpoint_id", endpoint.ID,
			"notification_endpoint_type", string(endpoint.Type),
		))
	}); err != nil {
		return domain.NotificationEndpoint{}, err
	}
	return endpoint, nil
}

func (s *Service) CreateCertificateProfile(ctx context.Context, actor string, req CreateCertificateProfileRequest) (domain.CertificateProfile, error) {
	if err := validateCreateCertificateProfileRequest(req); err != nil {
		return domain.CertificateProfile{}, err
	}

	now := s.clock.Now()
	profile := domain.CertificateProfile{
		ID:                     s.idgen.NewID(),
		Name:                   req.Name,
		Description:            req.Description,
		IssuerID:               req.IssuerID,
		ValidityPeriodSeconds:  req.ValidityPeriodSeconds,
		SubjectTemplate:        req.SubjectTemplate,
		AllowedDNSPatterns:     append([]string(nil), req.AllowedDNSPatterns...),
		AllowedIPRanges:        append([]string(nil), req.AllowedIPRanges...),
		KeyUsage:               copyStringListExtensionPolicy(req.KeyUsage),
		ExtendedKeyUsage:       copyStringListExtensionPolicy(req.ExtendedKeyUsage),
		BasicConstraints:       req.BasicConstraints,
		SubjectKeyIdentifier:   req.SubjectKeyIdentifier,
		AuthorityKeyIdentifier: req.AuthorityKeyIdentifier,
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		if err := repo.CreateCertificateProfile(ctx, profile); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "certificate_profile.created", "certificate_profile", profile.ID, now, auditFields(
			"issuer_id", profile.IssuerID,
			"profile_id", profile.ID,
		))
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
	if req.CertificateProfileID != "" {
		profile, err := s.repo.GetCertificateProfile(ctx, req.CertificateProfileID)
		if err != nil {
			return domain.Enrollment{}, err
		}
		if profile.IssuerID != req.IssuerID {
			return domain.Enrollment{}, domain.ErrInvalidRequest
		}
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
		CertificateProfileID: req.CertificateProfileID,
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
		return s.createAuditEvent(ctx, repo, actor, "enrollment.created", "enrollment", enrollment.ID, now, auditFields(
			"identity_id", enrollment.IdentityID,
			"issuer_id", enrollment.IssuerID,
			"enrollment_id", enrollment.ID,
			"profile_id", enrollment.CertificateProfileID,
		))
	}); err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (s *Service) RenewCertificate(ctx context.Context, actor string, certificateID string, req RenewCertificateRequest) (domain.Enrollment, error) {
	return s.createCertificateReplacementEnrollment(ctx, actor, certificateID, req.CSRPEM, req.RequestedNotAfter, "certificate.renewal_requested")
}

func (s *Service) ReissueCertificate(ctx context.Context, actor string, certificateID string, req ReissueCertificateRequest) (domain.Enrollment, error) {
	if isBlank(certificateID) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}
	certificate, err := s.repo.GetCertificate(ctx, certificateID)
	if err != nil {
		return domain.Enrollment{}, err
	}
	return s.createCertificateReplacementEnrollment(ctx, actor, certificateID, req.CSRPEM, certificate.NotAfter, "certificate.reissue_requested")
}

func (s *Service) ScanCertificateExpirations(ctx context.Context, actor string, req ScanCertificateExpirationsRequest) (CertificateExpirationScanResult, error) {
	if req.WarningWindow < 0 || req.Limit <= 0 {
		return CertificateExpirationScanResult{}, domain.ErrInvalidRequest
	}

	now := s.clock.Now()
	warningBefore := now.Add(req.WarningWindow)
	result := CertificateExpirationScanResult{
		Expired:            make([]domain.Certificate, 0),
		ExpirationWarnings: make([]domain.Certificate, 0),
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		candidates, err := repo.ListCertificatesForExpirationScan(ctx, now, warningBefore, req.Limit)
		if err != nil {
			return err
		}
		for _, certificate := range candidates {
			switch {
			case certificateIsExpiredCandidate(certificate, now):
				updated := certificate
				updated.Status = domain.CertificateExpired
				updated.UpdatedAt = now
				if err := repo.UpdateCertificateIfStatus(ctx, updated, certificate.Status); err != nil {
					if errors.Is(err, domain.ErrInvalidTransition) {
						continue
					}
					return err
				}
				fields := certificateExpirationAuditFields(updated, req.WarningWindow)
				if err := s.createAuditEvent(ctx, repo, actor, "certificate.expired", "certificate", updated.ID, now, fields); err != nil {
					return err
				}
				if err := s.createOutboxMessage(ctx, repo, "certificate.expired", now, fields); err != nil {
					return err
				}
				result.Expired = append(result.Expired, updated)
			case certificateNeedsRenewalWarning(certificate, now, warningBefore):
				updated := certificate
				updated.RenewalNotifiedAt = now
				updated.UpdatedAt = now
				if err := repo.UpdateCertificateIfStatus(ctx, updated, domain.CertificateValid); err != nil {
					if errors.Is(err, domain.ErrInvalidTransition) {
						continue
					}
					return err
				}
				fields := certificateExpirationAuditFields(updated, req.WarningWindow)
				if err := s.createAuditEvent(ctx, repo, actor, "certificate.expiration_warning", "certificate", updated.ID, now, fields); err != nil {
					return err
				}
				if err := s.createOutboxMessage(ctx, repo, "certificate.expiration_warning", now, fields); err != nil {
					return err
				}
				result.ExpirationWarnings = append(result.ExpirationWarnings, updated)
			}
		}
		return nil
	}); err != nil {
		return CertificateExpirationScanResult{}, err
	}
	return result, nil
}

func (s *Service) createCertificateReplacementEnrollment(ctx context.Context, actor string, certificateID string, csrPEM string, requestedNotAfter time.Time, action string) (domain.Enrollment, error) {
	if isBlank(certificateID) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}
	certificate, err := s.repo.GetCertificate(ctx, certificateID)
	if err != nil {
		return domain.Enrollment{}, err
	}
	if certificate.Status != domain.CertificateValid {
		return domain.Enrollment{}, domain.ErrInvalidTransition
	}

	createReq := CreateEnrollmentRequest{
		IdentityID:           certificate.IdentityID,
		IssuerID:             certificate.IssuerID,
		CertificateProfileID: certificate.CertificateProfileID,
		CSRPEM:               csrPEM,
		RequestedSubject:     certificate.Subject,
		RequestedDNSNames:    append([]string(nil), certificate.DNSNames...),
		RequestedIPAddresses: append([]string(nil), certificate.IPAddresses...),
		RequestedNotAfter:    requestedNotAfter,
	}
	now := s.clock.Now()
	if err := validateCreateEnrollmentRequest(createReq, now); err != nil {
		return domain.Enrollment{}, err
	}

	csrInfo, err := s.issuer.InspectCSR(ctx, createReq.CSRPEM)
	if err != nil {
		return domain.Enrollment{}, mapCSRInspectError(err)
	}
	if !sameStringSet(createReq.RequestedDNSNames, csrInfo.DNSNames) || !sameStringSet(createReq.RequestedIPAddresses, csrInfo.IPAddresses) {
		return domain.Enrollment{}, domain.ErrInvalidRequest
	}

	enrollment := domain.Enrollment{
		ID:                   s.idgen.NewID(),
		IdentityID:           createReq.IdentityID,
		IssuerID:             createReq.IssuerID,
		CertificateProfileID: createReq.CertificateProfileID,
		CSRPEM:               createReq.CSRPEM,
		Status:               domain.EnrollmentPending,
		RequestedSubject:     createReq.RequestedSubject,
		RequestedDNSNames:    append([]string(nil), createReq.RequestedDNSNames...),
		RequestedIPAddresses: append([]string(nil), createReq.RequestedIPAddresses...),
		CSRDNSNames:          append([]string(nil), csrInfo.DNSNames...),
		CSRIPAddresses:       append([]string(nil), csrInfo.IPAddresses...),
		RequestedNotAfter:    createReq.RequestedNotAfter,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		currentCertificate, err := repo.GetCertificate(ctx, certificateID)
		if err != nil {
			return err
		}
		if currentCertificate.Status != domain.CertificateValid {
			return domain.ErrInvalidTransition
		}
		if _, err := repo.GetIdentity(ctx, enrollment.IdentityID); err != nil {
			return err
		}
		if _, err := repo.GetIssuer(ctx, enrollment.IssuerID); err != nil {
			return err
		}
		if enrollment.CertificateProfileID != "" {
			profile, err := repo.GetCertificateProfile(ctx, enrollment.CertificateProfileID)
			if err != nil {
				return err
			}
			if profile.IssuerID != enrollment.IssuerID {
				return domain.ErrInvalidRequest
			}
		}
		if err := repo.CreateEnrollment(ctx, enrollment); err != nil {
			return err
		}
		fields := auditFields(
			"identity_id", enrollment.IdentityID,
			"issuer_id", enrollment.IssuerID,
			"enrollment_id", enrollment.ID,
			"certificate_id", currentCertificate.ID,
			"serial_number", currentCertificate.SerialNumber,
			"profile_id", enrollment.CertificateProfileID,
		)
		if err := s.createAuditEvent(ctx, repo, actor, action, "enrollment", enrollment.ID, now, fields); err != nil {
			return err
		}
		return s.createOutboxMessage(ctx, repo, action, now, fields)
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
		return s.createAuditEvent(ctx, repo, actor, "enrollment.approved", "enrollment", enrollment.ID, now, auditFields(
			"identity_id", enrollment.IdentityID,
			"issuer_id", enrollment.IssuerID,
			"enrollment_id", enrollment.ID,
			"profile_id", enrollment.CertificateProfileID,
		))
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
		return s.createAuditEvent(ctx, repo, actor, "enrollment.rejected", "enrollment", enrollment.ID, now, auditFields(
			"identity_id", enrollment.IdentityID,
			"issuer_id", enrollment.IssuerID,
			"enrollment_id", enrollment.ID,
			"profile_id", enrollment.CertificateProfileID,
		))
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
	var profile domain.CertificateProfile
	if enrollment.CertificateProfileID != "" {
		profile, err = s.repo.GetCertificateProfile(ctx, enrollment.CertificateProfileID)
		if err != nil {
			return domain.Certificate{}, err
		}
	}

	now := s.clock.Now()
	// MVP limit: signing precedes DB commit; conditional finalization below prevents stale issuers from persisting duplicates.
	result, err := s.issuer.Issue(ctx, corecli.IssueRequest{
		CSRPEM:                     enrollment.CSRPEM,
		IssuerCertificatePEM:       issuer.CertificatePEM,
		IssuerKeyRef:               issuer.KeyRef,
		Subject:                    enrollment.RequestedSubject,
		DNSNames:                   append([]string(nil), enrollment.RequestedDNSNames...),
		IPAddresses:                append([]string(nil), enrollment.RequestedIPAddresses...),
		NotBefore:                  now,
		NotAfter:                   enrollment.RequestedNotAfter,
		SignatureAlgorithm:         "ecdsa_with_sha256",
		ProfileID:                  profile.ID,
		BasicConstraintsCritical:   profile.BasicConstraints.Critical,
		BasicConstraintsCA:         profile.BasicConstraints.CA,
		BasicConstraintsMaxPathLen: profile.BasicConstraints.MaxPathLen,
		KeyUsageCritical:           profile.KeyUsage.Critical,
		KeyUsage:                   append([]string(nil), profile.KeyUsage.Values...),
		ExtendedKeyUsageCritical:   profile.ExtendedKeyUsage.Critical,
		ExtendedKeyUsage:           append([]string(nil), profile.ExtendedKeyUsage.Values...),
		SubjectKeyIdentifier:       profile.SubjectKeyIdentifier,
		AuthorityKeyIdentifier:     profile.AuthorityKeyIdentifier,
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
			ID:                   s.idgen.NewID(),
			IdentityID:           currentEnrollment.IdentityID,
			IssuerID:             currentEnrollment.IssuerID,
			EnrollmentID:         currentEnrollment.ID,
			CertificateProfileID: currentEnrollment.CertificateProfileID,
			SerialNumber:         result.SerialNumber,
			Subject:              result.Subject,
			DNSNames:             append([]string(nil), currentEnrollment.RequestedDNSNames...),
			IPAddresses:          append([]string(nil), currentEnrollment.RequestedIPAddresses...),
			NotBefore:            result.NotBefore,
			NotAfter:             result.NotAfter,
			Status:               domain.CertificateValid,
			CertificatePEM:       result.CertificatePEM,
			CreatedAt:            now,
			UpdatedAt:            now,
		}

		if err := repo.CreateCertificate(ctx, certificate); err != nil {
			return err
		}

		return s.createAuditEvent(ctx, repo, actor, "certificate.issued", "certificate", certificate.ID, now, auditFields(
			"identity_id", certificate.IdentityID,
			"issuer_id", certificate.IssuerID,
			"enrollment_id", certificate.EnrollmentID,
			"certificate_id", certificate.ID,
			"serial_number", certificate.SerialNumber,
			"profile_id", certificate.CertificateProfileID,
		))
	}); err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) RevokeCertificate(ctx context.Context, actor string, certificateID string, reason domain.RevocationReason) (domain.Certificate, error) {
	return s.revokeCertificate(ctx, actor, certificateID, reason, false)
}

func (s *Service) ForceRevokeCertificate(ctx context.Context, actor string, certificateID string, reason domain.RevocationReason) (domain.Certificate, error) {
	return s.revokeCertificate(ctx, actor, certificateID, reason, true)
}

func (s *Service) SuspendCertificate(ctx context.Context, actor string, certificateID string) (domain.Certificate, error) {
	if isBlank(certificateID) {
		return domain.Certificate{}, domain.ErrInvalidRequest
	}
	return s.transitionCertificateStatus(ctx, actor, certificateID, domain.CertificateValid, domain.CertificateSuspended, "certificate.suspended")
}

func (s *Service) ResumeCertificate(ctx context.Context, actor string, certificateID string) (domain.Certificate, error) {
	if isBlank(certificateID) {
		return domain.Certificate{}, domain.ErrInvalidRequest
	}
	return s.transitionCertificateStatus(ctx, actor, certificateID, domain.CertificateSuspended, domain.CertificateValid, "certificate.resumed")
}

func (s *Service) revokeCertificate(ctx context.Context, actor string, certificateID string, reason domain.RevocationReason, force bool) (domain.Certificate, error) {
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
		if !canRevokeCertificateStatus(certificate.Status, force) {
			return domain.ErrInvalidTransition
		}
		currentStatus := certificate.Status

		certificate.Status = domain.CertificateRevoked
		certificate.UpdatedAt = now
		if err := repo.UpdateCertificateIfStatus(ctx, certificate, currentStatus); err != nil {
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

		action := "certificate.revoked"
		if force {
			action = "certificate.force_revoked"
		}
		fields := auditFields(
			"identity_id", certificate.IdentityID,
			"issuer_id", certificate.IssuerID,
			"enrollment_id", certificate.EnrollmentID,
			"certificate_id", certificate.ID,
			"serial_number", certificate.SerialNumber,
			"profile_id", certificate.CertificateProfileID,
		)
		if err := s.createAuditEvent(ctx, repo, actor, action, "certificate", certificate.ID, now, fields); err != nil {
			return err
		}
		return s.createOutboxMessage(ctx, repo, action, now, fields)
	}); err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (s *Service) transitionCertificateStatus(ctx context.Context, actor string, certificateID string, currentStatus domain.CertificateStatus, nextStatus domain.CertificateStatus, action string) (domain.Certificate, error) {
	var certificate domain.Certificate
	now := s.clock.Now()
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		var err error
		certificate, err = repo.GetCertificate(ctx, certificateID)
		if err != nil {
			return err
		}
		if certificate.Status != currentStatus {
			return domain.ErrInvalidTransition
		}
		certificate.Status = nextStatus
		certificate.UpdatedAt = now
		if err := repo.UpdateCertificateIfStatus(ctx, certificate, currentStatus); err != nil {
			return err
		}
		fields := auditFields(
			"identity_id", certificate.IdentityID,
			"issuer_id", certificate.IssuerID,
			"enrollment_id", certificate.EnrollmentID,
			"certificate_id", certificate.ID,
			"serial_number", certificate.SerialNumber,
			"profile_id", certificate.CertificateProfileID,
		)
		if err := s.createAuditEvent(ctx, repo, actor, action, "certificate", certificate.ID, now, fields); err != nil {
			return err
		}
		return s.createOutboxMessage(ctx, repo, action, now, fields)
	}); err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func canRevokeCertificateStatus(status domain.CertificateStatus, force bool) bool {
	if status == domain.CertificateValid {
		return true
	}
	return force && status == domain.CertificateSuspended
}

func (s *Service) PublishCRL(ctx context.Context, actor string, req PublishCRLRequest) (domain.CRLPublication, error) {
	now := s.clock.Now()
	if err := validatePublishCRLRequest(req, now); err != nil {
		return domain.CRLPublication{}, err
	}

	issuer, err := s.repo.GetIssuer(ctx, req.IssuerID)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	revokedEntries, err := s.repo.ListRevocationsByIssuer(ctx, req.IssuerID)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	existing, err := s.repo.ListCRLPublicationsByIssuer(ctx, req.IssuerID)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	crlNumber := nextCRLNumber(existing, req.DistributionPoint)

	revokedCertificates := make([]corecli.RevokedCertificate, 0, len(revokedEntries))
	for _, entry := range revokedEntries {
		revokedCertificates = append(revokedCertificates, corecli.RevokedCertificate{
			SerialNumber: entry.SerialNumber,
			RevokedAt:    entry.RevokedAt,
			Reason:       string(entry.Reason),
		})
	}
	result, err := s.issuer.GenerateCRL(ctx, corecli.GenerateCRLRequest{
		IssuerCertificatePEM: issuer.CertificatePEM,
		IssuerKeyRef:         issuer.KeyRef,
		CRLNumber:            crlNumber,
		ThisUpdate:           now,
		NextUpdate:           req.NextUpdate,
		RevokedCertificates:  revokedCertificates,
	})
	if err != nil {
		return domain.CRLPublication{}, mapCRLError(err)
	}

	publication := domain.CRLPublication{
		ID:                s.idgen.NewID(),
		IssuerID:          req.IssuerID,
		DistributionPoint: req.DistributionPoint,
		CRLNumber:         crlNumber,
		ThisUpdate:        now,
		NextUpdate:        req.NextUpdate,
		Status:            domain.CRLPublicationPublished,
		CRLPEM:            result.CRLPEM,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		if err := repo.CreateCRLPublication(ctx, publication); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "crl.published", "crl_publication", publication.ID, now, map[string]any{
			"issuer_id":          publication.IssuerID,
			"crl_publication_id": publication.ID,
			"distribution_point": publication.DistributionPoint,
			"crl_number":         publication.CRLNumber,
		})
	}); err != nil {
		return domain.CRLPublication{}, err
	}
	return publication, nil
}

func (s *Service) RespondOCSP(ctx context.Context, actor string, requestDER []byte) (OCSPResponse, error) {
	if len(requestDER) == 0 {
		return OCSPResponse{}, domain.ErrInvalidRequest
	}
	now := s.clock.Now()
	info, err := s.issuer.InspectOCSP(ctx, requestDER)
	if err != nil {
		return OCSPResponse{}, mapOCSPDecodeError(err)
	}
	if len(info.Certificates) == 0 {
		return OCSPResponse{}, domain.ErrInvalidRequest
	}

	statuses, issuerID, err := s.ocspCertificateStatuses(ctx, info.Certificates)
	if err != nil {
		return OCSPResponse{}, err
	}
	if issuerID == "" {
		return OCSPResponse{}, domain.ErrInvalidRequest
	}
	issuer, err := s.repo.GetIssuer(ctx, issuerID)
	if err != nil {
		return OCSPResponse{}, err
	}
	signer, err := s.ocspSignerForIssuer(ctx, issuer)
	if err != nil {
		return OCSPResponse{}, err
	}

	result, err := s.issuer.GenerateOCSPResponse(ctx, corecli.GenerateOCSPResponseRequest{
		RequestDER:           append([]byte(nil), requestDER...),
		IssuerCertificatePEM: signer.CertificatePEM,
		IssuerKeyRef:         signer.KeyRef,
		ThisUpdate:           now,
		NextUpdate:           now.Add(time.Hour),
		Certificates:         statuses,
	})
	if err != nil {
		return OCSPResponse{}, mapOCSPResponseError(err)
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		fields := map[string]any{
			"request_type":             "ocsp",
			"issuer_id":                issuerID,
			"requested_cert_count":     len(info.Certificates),
			"response_status":          "successful",
			"nonce_present":            info.HasNonce,
			"first_serial_number":      firstOCSPSerial(info.Certificates),
			"first_certificate_status": firstOCSPStatus(statuses),
			"certificates":             ocspAuditCertificates(info.Certificates, statuses),
			"responder_mode":           signer.ResponderMode,
		}
		if signer.ResponderID != "" {
			fields["responder_id"] = signer.ResponderID
		}
		return s.createAuditEvent(ctx, repo, actor, "ocsp.requested", "ocsp", s.idgen.NewID(), now, fields)
	}); err != nil {
		return OCSPResponse{}, err
	}

	return OCSPResponse{ResponseDER: result.ResponseDER}, nil
}

func (s *Service) ocspSignerForIssuer(ctx context.Context, issuer domain.Issuer) (ocspSigner, error) {
	responder, err := s.repo.GetActiveOCSPResponderByIssuer(ctx, issuer.ID)
	if err == nil {
		return ocspSigner{
			CertificatePEM: responder.CertificatePEM,
			KeyRef:         responder.KeyRef,
			ResponderMode:  "delegated",
			ResponderID:    responder.ID,
		}, nil
	}
	if errors.Is(err, domain.ErrOCSPResponderNotFound) {
		return ocspSigner{
			CertificatePEM: issuer.CertificatePEM,
			KeyRef:         issuer.KeyRef,
			ResponderMode:  "issuer_direct",
		}, nil
	}
	return ocspSigner{}, err
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

func (s *Service) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	if isBlank(id) {
		return domain.CRLPublication{}, domain.ErrInvalidRequest
	}
	return s.repo.GetCRLPublication(ctx, id)
}

func (s *Service) GetLatestCRLPublication(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	if isBlank(issuerID) {
		return domain.CRLPublication{}, domain.ErrInvalidRequest
	}
	return s.repo.GetLatestCRLPublicationByIssuer(ctx, issuerID)
}

func (s *Service) GetLatestCRLPublicationForDistributionPoint(ctx context.Context, issuerID string, distributionPoint string) (domain.CRLPublication, error) {
	if isBlank(issuerID) || isBlank(distributionPoint) {
		return domain.CRLPublication{}, domain.ErrInvalidRequest
	}
	publications, err := s.repo.ListCRLPublicationsByIssuer(ctx, issuerID)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	return latestCRLPublication(publications, distributionPoint)
}

func (s *Service) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repo.ListAuditEvents(ctx)
}

func (s *Service) RecordAPIFailure(ctx context.Context, actor string, req APIFailureAuditRequest) error {
	if isBlank(actor) {
		actor = "anonymous"
	}
	now := s.clock.Now()
	fields := map[string]any{
		"http_method": req.Method,
		"http_path":   req.Path,
		"http_status": req.StatusCode,
	}
	return s.repo.WithinTx(ctx, func(repo store.Repository) error {
		return s.createAuditEventWithResult(ctx, repo, actor, "api.request_failed", "api", s.idgen.NewID(), now, fields, "error", auditErrorCode(req.Err))
	})
}

func (s *Service) createAuditEvent(ctx context.Context, repo store.Repository, actor string, action string, resourceType string, resourceID string, createdAt time.Time, fields map[string]any) error {
	return s.createAuditEventWithResult(ctx, repo, actor, action, resourceType, resourceID, createdAt, fields, "ok", "")
}

func (s *Service) createAuditEventWithResult(ctx context.Context, repo store.Repository, actor string, action string, resourceType string, resourceID string, createdAt time.Time, fields map[string]any, resultCode string, errorCode string) error {
	return repo.CreateAuditEvent(ctx, domain.AuditEvent{
		ID:           s.idgen.NewID(),
		Actor:        actor,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		MetadataJSON: auditMetadataJSON(ctx, fields, resultCode, errorCode),
		CreatedAt:    createdAt,
	})
}

func (s *Service) createOutboxMessage(ctx context.Context, repo store.Repository, messageType string, createdAt time.Time, fields map[string]any) error {
	payload := make(map[string]any, len(fields)+1)
	for key, value := range fields {
		payload[key] = value
	}
	payload["event_type"] = messageType

	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return repo.CreateOutboxMessage(ctx, domain.OutboxMessage{
		ID:          s.idgen.NewID(),
		Type:        messageType,
		PayloadJSON: string(encoded),
		Status:      domain.OutboxPending,
		AvailableAt: createdAt,
		MaxAttempts: defaultOutboxMaxAttempts,
		CreatedAt:   createdAt,
		UpdatedAt:   createdAt,
	})
}

func auditFields(pairs ...string) map[string]any {
	fields := make(map[string]any)
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i] != "" && pairs[i+1] != "" {
			fields[pairs[i]] = pairs[i+1]
		}
	}
	return fields
}

func certificateExpirationAuditFields(certificate domain.Certificate, warningWindow time.Duration) map[string]any {
	fields := auditFields(
		"identity_id", certificate.IdentityID,
		"issuer_id", certificate.IssuerID,
		"enrollment_id", certificate.EnrollmentID,
		"certificate_id", certificate.ID,
		"serial_number", certificate.SerialNumber,
		"profile_id", certificate.CertificateProfileID,
	)
	fields["not_after"] = certificate.NotAfter.Format(time.RFC3339)
	fields["warning_window_seconds"] = int64(warningWindow.Seconds())
	return fields
}

func certificateIsExpiredCandidate(certificate domain.Certificate, now time.Time) bool {
	return (certificate.Status == domain.CertificateValid || certificate.Status == domain.CertificateSuspended) && !certificate.NotAfter.After(now)
}

func certificateNeedsRenewalWarning(certificate domain.Certificate, now time.Time, warningBefore time.Time) bool {
	return certificate.Status == domain.CertificateValid &&
		certificate.NotAfter.After(now) &&
		!certificate.NotAfter.After(warningBefore) &&
		certificate.RenewalNotifiedAt.IsZero()
}

func auditMetadataJSON(ctx context.Context, fields map[string]any, resultCode string, errorCode string) string {
	metadata := make(map[string]any, len(fields)+4)
	for key, value := range fields {
		metadata[key] = value
	}
	metadata["result_code"] = resultCode
	if errorCode != "" {
		metadata["error_code"] = errorCode
	}
	if requestMetadata, ok := ctx.Value(auditRequestMetadataContextKey{}).(AuditRequestMetadata); ok {
		if requestMetadata.RequestID != "" {
			metadata["request_id"] = requestMetadata.RequestID
		}
		if requestMetadata.ClientIP != "" {
			metadata["client_ip"] = requestMetadata.ClientIP
		}
		if !requestMetadata.StartedAt.IsZero() {
			metadata["elapsed_ms"] = time.Since(requestMetadata.StartedAt).Milliseconds()
		}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func auditErrorCode(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest):
		return "invalid_request"
	case errors.Is(err, domain.ErrUnsupportedMediaType):
		return "unsupported_media_type"
	case errors.Is(err, domain.ErrInvalidTransition):
		return "invalid_lifecycle_transition"
	case errors.Is(err, domain.ErrIdentityNotFound):
		return "identity_not_found"
	case errors.Is(err, domain.ErrIssuerNotFound):
		return "issuer_not_found"
	case errors.Is(err, domain.ErrOCSPResponderNotFound):
		return "ocsp_responder_not_found"
	case errors.Is(err, domain.ErrCertificateProfileNotFound):
		return "certificate_profile_not_found"
	case errors.Is(err, domain.ErrEnrollmentNotFound):
		return "enrollment_not_found"
	case errors.Is(err, domain.ErrCertificateNotFound):
		return "certificate_not_found"
	case errors.Is(err, domain.ErrCRLPublicationNotFound):
		return "crl_publication_not_found"
	case errors.Is(err, domain.ErrCSRParseFailed):
		return "csr_parse_failed"
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return "certificate_issuance_failed"
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return "crl_generation_failed"
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return "ocsp_decode_failed"
	case errors.Is(err, domain.ErrOCSPResponderValidationFailed):
		return "ocsp_responder_validation_failed"
	case errors.Is(err, domain.ErrOCSPResponseFailed):
		return "ocsp_response_failed"
	case errors.Is(err, domain.ErrStorageFailure):
		return "storage_failure"
	default:
		return "internal"
	}
}

func (s *Service) ocspCertificateStatuses(ctx context.Context, ids []corecli.OCSPCertificateID) ([]corecli.OCSPCertificateStatus, string, error) {
	issuersByHash, err := s.ocspIssuersByHash(ctx, ids)
	if err != nil {
		return nil, "", err
	}
	certificates, err := s.repo.ListCertificates(ctx)
	if err != nil {
		return nil, "", err
	}
	byIssuerSerial := make(map[string]domain.Certificate, len(certificates))
	for _, certificate := range certificates {
		key := ocspIssuerSerialKey(certificate.IssuerID, certificate.SerialNumber)
		if _, exists := byIssuerSerial[key]; !exists {
			byIssuerSerial[key] = certificate
		}
	}

	statuses := make([]corecli.OCSPCertificateStatus, 0, len(ids))
	issuerID := ""
	revocationsByIssuer := make(map[string][]domain.RevokedCertificateEntry)
	for _, id := range ids {
		issuer, issuerFound := issuersByHash[ocspIssuerHashKey(id.HashAlgorithm, id.IssuerNameHash, id.IssuerKeyHash)]
		if !issuerFound {
			statuses = append(statuses, unknownOCSPStatus(id))
			continue
		}
		if issuerID == "" {
			issuerID = issuer.ID
		}
		if issuerID != issuer.ID {
			return nil, "", domain.ErrInvalidRequest
		}
		certificate, found := byIssuerSerial[ocspIssuerSerialKey(issuer.ID, id.SerialNumber)]
		if !found {
			statuses = append(statuses, unknownOCSPStatus(id))
			continue
		}
		switch certificate.Status {
		case domain.CertificateValid:
			statuses = append(statuses, ocspStatusForID(id, "good"))
		case domain.CertificateRevoked:
			revocations, ok := revocationsByIssuer[certificate.IssuerID]
			if !ok {
				revocations, err = s.repo.ListRevocationsByIssuer(ctx, certificate.IssuerID)
				if err != nil {
					return nil, "", err
				}
				revocationsByIssuer[certificate.IssuerID] = revocations
			}
			statuses = append(statuses, revokedOCSPStatus(id, certificate, revocations))
		default:
			statuses = append(statuses, unknownOCSPStatus(id))
		}
	}
	return statuses, issuerID, nil
}

func (s *Service) ocspIssuersByHash(ctx context.Context, ids []corecli.OCSPCertificateID) (map[string]domain.Issuer, error) {
	issuers, err := s.repo.ListIssuers(ctx)
	if err != nil {
		return nil, err
	}
	hashAlgorithms := ocspHashAlgorithms(ids)
	byHash := make(map[string]domain.Issuer, len(issuers)*len(hashAlgorithms))
	for _, issuer := range issuers {
		if issuer.Status != domain.IssuerActive {
			continue
		}
		for _, hashAlgorithm := range hashAlgorithms {
			info, err := s.issuer.InspectOCSPIssuer(ctx, issuer.CertificatePEM, hashAlgorithm)
			if err != nil {
				return nil, mapOCSPDecodeError(err)
			}
			byHash[ocspIssuerHashKey(hashAlgorithm, info.IssuerNameHash, info.IssuerKeyHash)] = issuer
		}
	}
	return byHash, nil
}

func ocspIssuerHashKey(hashAlgorithm string, nameHash string, keyHash string) string {
	return normalizeOCSPHashAlgorithm(hashAlgorithm) + "\x00" + nameHash + "\x00" + keyHash
}

func ocspIssuerSerialKey(issuerID string, serialNumber string) string {
	return issuerID + "\x00" + serialNumber
}

func unknownOCSPStatus(id corecli.OCSPCertificateID) corecli.OCSPCertificateStatus {
	return ocspStatusForID(id, "unknown")
}

func ocspStatusForID(id corecli.OCSPCertificateID, status string) corecli.OCSPCertificateStatus {
	return corecli.OCSPCertificateStatus{
		SerialNumber:   id.SerialNumber,
		Status:         status,
		HashAlgorithm:  normalizeOCSPHashAlgorithm(id.HashAlgorithm),
		IssuerNameHash: id.IssuerNameHash,
		IssuerKeyHash:  id.IssuerKeyHash,
	}
}

func revokedOCSPStatus(id corecli.OCSPCertificateID, certificate domain.Certificate, revocations []domain.RevokedCertificateEntry) corecli.OCSPCertificateStatus {
	status := ocspStatusForID(id, "revoked")
	for _, revocation := range revocations {
		if revocation.SerialNumber == certificate.SerialNumber {
			status.RevokedAt = revocation.RevokedAt
			status.RevocationReason = string(revocation.Reason)
			return status
		}
	}
	return status
}

func ocspHashAlgorithms(ids []corecli.OCSPCertificateID) []string {
	seen := make(map[string]bool)
	algorithms := make([]string, 0, len(ids))
	for _, id := range ids {
		algorithm := normalizeOCSPHashAlgorithm(id.HashAlgorithm)
		if !seen[algorithm] {
			seen[algorithm] = true
			algorithms = append(algorithms, algorithm)
		}
	}
	if len(algorithms) == 0 {
		return []string{"sha1"}
	}
	return algorithms
}

func normalizeOCSPHashAlgorithm(hashAlgorithm string) string {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(hashAlgorithm, "-", ""), "_", ""))
	if normalized == "" {
		return "sha1"
	}
	return normalized
}

func firstOCSPSerial(ids []corecli.OCSPCertificateID) string {
	if len(ids) == 0 {
		return ""
	}
	return ids[0].SerialNumber
}

func firstOCSPStatus(statuses []corecli.OCSPCertificateStatus) string {
	if len(statuses) == 0 {
		return ""
	}
	return statuses[0].Status
}

func ocspAuditCertificates(ids []corecli.OCSPCertificateID, statuses []corecli.OCSPCertificateStatus) []map[string]any {
	entries := make([]map[string]any, 0, len(ids))
	for i, id := range ids {
		entry := map[string]any{
			"serial_number":    id.SerialNumber,
			"issuer_name_hash": id.IssuerNameHash,
			"issuer_key_hash":  id.IssuerKeyHash,
			"hash_algorithm":   normalizeOCSPHashAlgorithm(id.HashAlgorithm),
		}
		if i < len(statuses) {
			status := statuses[i]
			entry["status"] = status.Status
			if status.RevocationReason != "" {
				entry["reason"] = status.RevocationReason
			}
			if !status.RevokedAt.IsZero() {
				entry["revoked_at"] = status.RevokedAt.Format(time.RFC3339)
			}
		}
		entries = append(entries, entry)
	}
	return entries
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

func validateCreateNotificationEndpointRequest(req CreateNotificationEndpointRequest) error {
	if isBlank(req.Name) || isBlank(req.URL) {
		return domain.ErrInvalidRequest
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return domain.ErrInvalidRequest
	}
	for _, eventType := range req.EventTypes {
		if isBlank(eventType) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func validateCreateCertificateProfileRequest(req CreateCertificateProfileRequest) error {
	if isBlank(req.Name) || isBlank(req.IssuerID) || req.ValidityPeriodSeconds <= 0 {
		return domain.ErrInvalidRequest
	}
	if req.BasicConstraints.MaxPathLen != nil {
		if *req.BasicConstraints.MaxPathLen < 0 || !req.BasicConstraints.CA {
			return domain.ErrInvalidRequest
		}
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

func validatePublishCRLRequest(req PublishCRLRequest, now time.Time) error {
	if isBlank(req.IssuerID) || isBlank(req.DistributionPoint) {
		return domain.ErrInvalidRequest
	}
	if !req.NextUpdate.After(now) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func nextCRLNumber(publications []domain.CRLPublication, distributionPoint string) int64 {
	var maxNumber int64
	for _, publication := range publications {
		if publication.DistributionPoint == distributionPoint && publication.CRLNumber > maxNumber {
			maxNumber = publication.CRLNumber
		}
	}
	return maxNumber + 1
}

func latestCRLPublication(publications []domain.CRLPublication, distributionPoint string) (domain.CRLPublication, error) {
	var latest domain.CRLPublication
	found := false
	for _, publication := range publications {
		if publication.DistributionPoint != distributionPoint {
			continue
		}
		if !found || publication.CRLNumber > latest.CRLNumber ||
			(publication.CRLNumber == latest.CRLNumber && publication.CreatedAt.After(latest.CreatedAt)) {
			latest = publication
			found = true
		}
	}
	if !found {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return latest, nil
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

func isValidOutboxMessageStatus(status domain.OutboxMessageStatus) bool {
	switch status {
	case domain.OutboxPending, domain.OutboxProcessing, domain.OutboxCompleted, domain.OutboxFailed, domain.OutboxDeadLetter:
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

func mapCRLError(err error) error {
	return fmt.Errorf("%w: %w", domain.ErrCRLGenerationFailed, err)
}

func mapOCSPDecodeError(err error) error {
	return fmt.Errorf("%w: %w", domain.ErrOCSPDecodeFailed, err)
}

func mapOCSPResponseError(err error) error {
	return fmt.Errorf("%w: %w", domain.ErrOCSPResponseFailed, err)
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
