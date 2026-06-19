package store

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
)

type MemoryStore struct {
	mu sync.RWMutex

	identities     map[string]domain.Identity
	issuers        map[string]domain.Issuer
	ocspResponders map[string]domain.OCSPResponder
	notifications  map[string]domain.NotificationEndpoint
	profiles       map[string]domain.CertificateProfile
	enrollments    map[string]domain.Enrollment
	certificates   map[string]domain.Certificate
	revocations    map[string]domain.Revocation
	crls           map[string]domain.CRLPublication
	auditEvents    []domain.AuditEvent
	outbox         map[string]domain.OutboxMessage
	jobAttempts    map[string]domain.JobAttempt
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities:     make(map[string]domain.Identity),
		issuers:        make(map[string]domain.Issuer),
		ocspResponders: make(map[string]domain.OCSPResponder),
		notifications:  make(map[string]domain.NotificationEndpoint),
		profiles:       make(map[string]domain.CertificateProfile),
		enrollments:    make(map[string]domain.Enrollment),
		certificates:   make(map[string]domain.Certificate),
		revocations:    make(map[string]domain.Revocation),
		crls:           make(map[string]domain.CRLPublication),
		auditEvents:    make([]domain.AuditEvent, 0),
		outbox:         make(map[string]domain.OutboxMessage),
		jobAttempts:    make(map[string]domain.JobAttempt),
	}
}

func (s *MemoryStore) WithinTx(ctx context.Context, fn func(Repository) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx := &memoryTx{
		identities:     cloneIdentities(s.identities),
		issuers:        cloneIssuers(s.issuers),
		ocspResponders: cloneOCSPResponders(s.ocspResponders),
		notifications:  cloneNotificationEndpoints(s.notifications),
		profiles:       cloneCertificateProfiles(s.profiles),
		enrollments:    cloneEnrollments(s.enrollments),
		certificates:   cloneCertificates(s.certificates),
		revocations:    cloneRevocations(s.revocations),
		crls:           cloneCRLPublications(s.crls),
		auditEvents:    cloneAuditEvents(s.auditEvents),
		outbox:         cloneOutboxMessages(s.outbox),
		jobAttempts:    cloneJobAttempts(s.jobAttempts),
	}
	if err := fn(tx); err != nil {
		return err
	}

	s.identities = tx.identities
	s.issuers = tx.issuers
	s.ocspResponders = tx.ocspResponders
	s.notifications = tx.notifications
	s.profiles = tx.profiles
	s.enrollments = tx.enrollments
	s.certificates = tx.certificates
	s.revocations = tx.revocations
	s.crls = tx.crls
	s.auditEvents = tx.auditEvents
	s.outbox = tx.outbox
	s.jobAttempts = tx.jobAttempts
	return nil
}

func (s *MemoryStore) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.identities[identity.ID] = identity
	return nil
}

func (s *MemoryStore) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, ok := s.identities[id]
	if !ok {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	return identity, nil
}

func (s *MemoryStore) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identities := make([]domain.Identity, 0, len(s.identities))
	for _, identity := range s.identities {
		identities = append(identities, identity)
	}
	return identities, nil
}

func (s *MemoryStore) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.issuers[issuer.ID] = issuer
	return nil
}

func (s *MemoryStore) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuer, ok := s.issuers[id]
	if !ok {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	return issuer, nil
}

func (s *MemoryStore) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	issuers := make([]domain.Issuer, 0, len(s.issuers))
	for _, issuer := range s.issuers {
		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

func (s *MemoryStore) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if responder.Status == domain.OCSPResponderActive {
		if _, err := activeOCSPResponderByIssuer(s.ocspResponders, responder.IssuerID); err == nil {
			return domain.ErrInvalidTransition
		}
	}
	s.ocspResponders[responder.ID] = responder
	return nil
}

func (s *MemoryStore) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	responder, ok := s.ocspResponders[id]
	if !ok {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return responder, nil
}

func (s *MemoryStore) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listOCSPRespondersByIssuer(s.ocspResponders, issuerID), nil
}

func (s *MemoryStore) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return activeOCSPResponderByIssuer(s.ocspResponders, issuerID)
}

func (s *MemoryStore) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateOCSPResponderIfStatus(s.ocspResponders, responder, currentStatus)
}

func (s *MemoryStore) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.notifications[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func (s *MemoryStore) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	endpoint, ok := s.notifications[id]
	if !ok {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	return copyNotificationEndpoint(endpoint), nil
}

func (s *MemoryStore) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listNotificationEndpoints(s.notifications), nil
}

func (s *MemoryStore) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateNotificationEndpointIfStatus(s.notifications, endpoint, currentStatus)
}

func (s *MemoryStore) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.profiles[profile.ID] = copyCertificateProfile(profile)
	return nil
}

func (s *MemoryStore) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profile, ok := s.profiles[id]
	if !ok {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	return copyCertificateProfile(profile), nil
}

func (s *MemoryStore) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	profiles := make([]domain.CertificateProfile, 0, len(s.profiles))
	for _, profile := range s.profiles {
		profiles = append(profiles, copyCertificateProfile(profile))
	}
	return profiles, nil
}

func (s *MemoryStore) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (s *MemoryStore) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollment, ok := s.enrollments[id]
	if !ok {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	return copyEnrollment(enrollment), nil
}

func (s *MemoryStore) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	enrollments := make([]domain.Enrollment, 0, len(s.enrollments))
	for _, enrollment := range s.enrollments {
		enrollments = append(enrollments, copyEnrollment(enrollment))
	}
	return enrollments, nil
}

func (s *MemoryStore) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.enrollments[enrollment.ID]; !ok {
		return domain.ErrEnrollmentNotFound
	}
	s.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (s *MemoryStore) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateEnrollmentIfStatus(s.enrollments, enrollment, currentStatus)
}

func (s *MemoryStore) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (s *MemoryStore) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certificate, ok := s.certificates[id]
	if !ok {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	return copyCertificate(certificate), nil
}

func (s *MemoryStore) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certificates := make([]domain.Certificate, 0, len(s.certificates))
	for _, certificate := range s.certificates {
		certificates = append(certificates, copyCertificate(certificate))
	}
	return certificates, nil
}

func (s *MemoryStore) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCertificatesForExpirationScan(s.certificates, now, warningBefore, limit), nil
}

func (s *MemoryStore) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.certificates[certificate.ID]; !ok {
		return domain.ErrCertificateNotFound
	}
	s.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (s *MemoryStore) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateCertificateIfStatus(s.certificates, certificate, currentStatus)
}

func (s *MemoryStore) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.revocations[revocation.ID] = revocation
	return nil
}

func (s *MemoryStore) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listRevocationsByIssuer(s.certificates, s.revocations, issuerID), nil
}

func (s *MemoryStore) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.crls[publication.ID] = publication
	return nil
}

func (s *MemoryStore) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	publication, ok := s.crls[id]
	if !ok {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return publication, nil
}

func (s *MemoryStore) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return latestCRLPublicationByIssuer(s.crls, issuerID)
}

func (s *MemoryStore) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listCRLPublicationsByIssuer(s.crls, issuerID), nil
}

func (s *MemoryStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *MemoryStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := make([]domain.AuditEvent, len(s.auditEvents))
	copy(events, s.auditEvents)
	return events, nil
}

func (s *MemoryStore) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.outbox[message.ID] = message
	return nil
}

func (s *MemoryStore) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listDueOutboxMessages(s.outbox, now, limit), nil
}

func (s *MemoryStore) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return updateOutboxMessageStatusIfStatus(s.outbox, message, currentStatus)
}

func (s *MemoryStore) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.jobAttempts[attempt.ID] = attempt
	return nil
}

func (s *MemoryStore) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return listJobAttemptsByOutboxMessage(s.jobAttempts, outboxMessageID), nil
}

func copyEnrollment(enrollment domain.Enrollment) domain.Enrollment {
	enrollment.RequestedDNSNames = append([]string(nil), enrollment.RequestedDNSNames...)
	enrollment.RequestedIPAddresses = append([]string(nil), enrollment.RequestedIPAddresses...)
	enrollment.CSRDNSNames = append([]string(nil), enrollment.CSRDNSNames...)
	enrollment.CSRIPAddresses = append([]string(nil), enrollment.CSRIPAddresses...)
	return enrollment
}

func copyCertificateProfile(profile domain.CertificateProfile) domain.CertificateProfile {
	profile.AllowedDNSPatterns = append([]string(nil), profile.AllowedDNSPatterns...)
	profile.AllowedIPRanges = append([]string(nil), profile.AllowedIPRanges...)
	profile.KeyUsage.Values = append([]string(nil), profile.KeyUsage.Values...)
	profile.ExtendedKeyUsage.Values = append([]string(nil), profile.ExtendedKeyUsage.Values...)
	return profile
}

func copyCertificate(certificate domain.Certificate) domain.Certificate {
	certificate.DNSNames = append([]string(nil), certificate.DNSNames...)
	certificate.IPAddresses = append([]string(nil), certificate.IPAddresses...)
	return certificate
}

func copyNotificationEndpoint(endpoint domain.NotificationEndpoint) domain.NotificationEndpoint {
	endpoint.EventTypes = append([]string(nil), endpoint.EventTypes...)
	return endpoint
}

func updateEnrollmentIfStatus(enrollments map[string]domain.Enrollment, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	current, ok := enrollments[enrollment.ID]
	if !ok {
		return domain.ErrEnrollmentNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func updateCertificateIfStatus(certificates map[string]domain.Certificate, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	current, ok := certificates[certificate.ID]
	if !ok {
		return domain.ErrCertificateNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func updateOCSPResponderIfStatus(responders map[string]domain.OCSPResponder, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	current, ok := responders[responder.ID]
	if !ok {
		return domain.ErrOCSPResponderNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	if responder.Status == domain.OCSPResponderActive {
		if active, err := activeOCSPResponderByIssuer(responders, responder.IssuerID); err == nil && active.ID != responder.ID {
			return domain.ErrInvalidTransition
		}
	}
	responders[responder.ID] = responder
	return nil
}

func updateNotificationEndpointIfStatus(endpoints map[string]domain.NotificationEndpoint, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	current, ok := endpoints[endpoint.ID]
	if !ok {
		return domain.ErrNotificationEndpointNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	endpoints[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func listNotificationEndpoints(endpoints map[string]domain.NotificationEndpoint) []domain.NotificationEndpoint {
	result := make([]domain.NotificationEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		result = append(result, copyNotificationEndpoint(endpoint))
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func listDueOutboxMessages(messages map[string]domain.OutboxMessage, now time.Time, limit int) []domain.OutboxMessage {
	if limit <= 0 {
		return nil
	}

	due := make([]domain.OutboxMessage, 0)
	for _, message := range messages {
		if message.Status != domain.OutboxPending || message.AvailableAt.After(now) {
			continue
		}
		due = append(due, message)
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].AvailableAt.Equal(due[j].AvailableAt) {
			return due[i].AvailableAt.Before(due[j].AvailableAt)
		}
		if !due[i].CreatedAt.Equal(due[j].CreatedAt) {
			return due[i].CreatedAt.Before(due[j].CreatedAt)
		}
		return due[i].ID < due[j].ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	return due
}

func updateOutboxMessageStatusIfStatus(messages map[string]domain.OutboxMessage, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	current, ok := messages[message.ID]
	if !ok {
		return domain.ErrOutboxMessageNotFound
	}
	if current.Status != currentStatus {
		return domain.ErrInvalidTransition
	}
	messages[message.ID] = message
	return nil
}

func listJobAttemptsByOutboxMessage(attempts map[string]domain.JobAttempt, outboxMessageID string) []domain.JobAttempt {
	result := make([]domain.JobAttempt, 0)
	for _, attempt := range attempts {
		if attempt.OutboxMessageID == outboxMessageID {
			result = append(result, attempt)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

type memoryTx struct {
	identities     map[string]domain.Identity
	issuers        map[string]domain.Issuer
	ocspResponders map[string]domain.OCSPResponder
	notifications  map[string]domain.NotificationEndpoint
	profiles       map[string]domain.CertificateProfile
	enrollments    map[string]domain.Enrollment
	certificates   map[string]domain.Certificate
	revocations    map[string]domain.Revocation
	crls           map[string]domain.CRLPublication
	auditEvents    []domain.AuditEvent
	outbox         map[string]domain.OutboxMessage
	jobAttempts    map[string]domain.JobAttempt
}

func (tx *memoryTx) WithinTx(ctx context.Context, fn func(Repository) error) error {
	return fn(tx)
}

func (tx *memoryTx) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	tx.identities[identity.ID] = identity
	return nil
}

func (tx *memoryTx) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	identity, ok := tx.identities[id]
	if !ok {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	return identity, nil
}

func (tx *memoryTx) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	identities := make([]domain.Identity, 0, len(tx.identities))
	for _, identity := range tx.identities {
		identities = append(identities, identity)
	}
	return identities, nil
}

func (tx *memoryTx) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	tx.issuers[issuer.ID] = issuer
	return nil
}

func (tx *memoryTx) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	issuer, ok := tx.issuers[id]
	if !ok {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	return issuer, nil
}

func (tx *memoryTx) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	issuers := make([]domain.Issuer, 0, len(tx.issuers))
	for _, issuer := range tx.issuers {
		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

func (tx *memoryTx) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	if responder.Status == domain.OCSPResponderActive {
		if _, err := activeOCSPResponderByIssuer(tx.ocspResponders, responder.IssuerID); err == nil {
			return domain.ErrInvalidTransition
		}
	}
	tx.ocspResponders[responder.ID] = responder
	return nil
}

func (tx *memoryTx) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	responder, ok := tx.ocspResponders[id]
	if !ok {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return responder, nil
}

func (tx *memoryTx) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	return listOCSPRespondersByIssuer(tx.ocspResponders, issuerID), nil
}

func (tx *memoryTx) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	return activeOCSPResponderByIssuer(tx.ocspResponders, issuerID)
}

func (tx *memoryTx) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	return updateOCSPResponderIfStatus(tx.ocspResponders, responder, currentStatus)
}

func (tx *memoryTx) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	tx.notifications[endpoint.ID] = copyNotificationEndpoint(endpoint)
	return nil
}

func (tx *memoryTx) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	endpoint, ok := tx.notifications[id]
	if !ok {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	return copyNotificationEndpoint(endpoint), nil
}

func (tx *memoryTx) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	return listNotificationEndpoints(tx.notifications), nil
}

func (tx *memoryTx) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	return updateNotificationEndpointIfStatus(tx.notifications, endpoint, currentStatus)
}

func (tx *memoryTx) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	tx.profiles[profile.ID] = copyCertificateProfile(profile)
	return nil
}

func (tx *memoryTx) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	profile, ok := tx.profiles[id]
	if !ok {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	return copyCertificateProfile(profile), nil
}

func (tx *memoryTx) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	profiles := make([]domain.CertificateProfile, 0, len(tx.profiles))
	for _, profile := range tx.profiles {
		profiles = append(profiles, copyCertificateProfile(profile))
	}
	return profiles, nil
}

func (tx *memoryTx) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	tx.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (tx *memoryTx) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	enrollment, ok := tx.enrollments[id]
	if !ok {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	return copyEnrollment(enrollment), nil
}

func (tx *memoryTx) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	enrollments := make([]domain.Enrollment, 0, len(tx.enrollments))
	for _, enrollment := range tx.enrollments {
		enrollments = append(enrollments, copyEnrollment(enrollment))
	}
	return enrollments, nil
}

func (tx *memoryTx) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	if _, ok := tx.enrollments[enrollment.ID]; !ok {
		return domain.ErrEnrollmentNotFound
	}
	tx.enrollments[enrollment.ID] = copyEnrollment(enrollment)
	return nil
}

func (tx *memoryTx) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	return updateEnrollmentIfStatus(tx.enrollments, enrollment, currentStatus)
}

func (tx *memoryTx) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	tx.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (tx *memoryTx) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	certificate, ok := tx.certificates[id]
	if !ok {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	return copyCertificate(certificate), nil
}

func (tx *memoryTx) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	certificates := make([]domain.Certificate, 0, len(tx.certificates))
	for _, certificate := range tx.certificates {
		certificates = append(certificates, copyCertificate(certificate))
	}
	return certificates, nil
}

func (tx *memoryTx) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	return listCertificatesForExpirationScan(tx.certificates, now, warningBefore, limit), nil
}

func (tx *memoryTx) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	if _, ok := tx.certificates[certificate.ID]; !ok {
		return domain.ErrCertificateNotFound
	}
	tx.certificates[certificate.ID] = copyCertificate(certificate)
	return nil
}

func (tx *memoryTx) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	return updateCertificateIfStatus(tx.certificates, certificate, currentStatus)
}

func (tx *memoryTx) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	tx.revocations[revocation.ID] = revocation
	return nil
}

func (tx *memoryTx) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	return listRevocationsByIssuer(tx.certificates, tx.revocations, issuerID), nil
}

func (tx *memoryTx) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	tx.crls[publication.ID] = publication
	return nil
}

func (tx *memoryTx) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	publication, ok := tx.crls[id]
	if !ok {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return publication, nil
}

func (tx *memoryTx) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	return latestCRLPublicationByIssuer(tx.crls, issuerID)
}

func (tx *memoryTx) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	return listCRLPublicationsByIssuer(tx.crls, issuerID), nil
}

func (tx *memoryTx) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	tx.auditEvents = append(tx.auditEvents, event)
	return nil
}

func (tx *memoryTx) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	events := make([]domain.AuditEvent, len(tx.auditEvents))
	copy(events, tx.auditEvents)
	return events, nil
}

func (tx *memoryTx) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	tx.outbox[message.ID] = message
	return nil
}

func (tx *memoryTx) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	return listDueOutboxMessages(tx.outbox, now, limit), nil
}

func (tx *memoryTx) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	return updateOutboxMessageStatusIfStatus(tx.outbox, message, currentStatus)
}

func (tx *memoryTx) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	tx.jobAttempts[attempt.ID] = attempt
	return nil
}

func (tx *memoryTx) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	return listJobAttemptsByOutboxMessage(tx.jobAttempts, outboxMessageID), nil
}

func cloneIdentities(src map[string]domain.Identity) map[string]domain.Identity {
	dst := make(map[string]domain.Identity, len(src))
	for id, identity := range src {
		dst[id] = identity
	}
	return dst
}

func cloneIssuers(src map[string]domain.Issuer) map[string]domain.Issuer {
	dst := make(map[string]domain.Issuer, len(src))
	for id, issuer := range src {
		dst[id] = issuer
	}
	return dst
}

func cloneOCSPResponders(src map[string]domain.OCSPResponder) map[string]domain.OCSPResponder {
	dst := make(map[string]domain.OCSPResponder, len(src))
	for id, responder := range src {
		dst[id] = responder
	}
	return dst
}

func cloneNotificationEndpoints(src map[string]domain.NotificationEndpoint) map[string]domain.NotificationEndpoint {
	dst := make(map[string]domain.NotificationEndpoint, len(src))
	for id, endpoint := range src {
		dst[id] = copyNotificationEndpoint(endpoint)
	}
	return dst
}

func cloneCertificateProfiles(src map[string]domain.CertificateProfile) map[string]domain.CertificateProfile {
	dst := make(map[string]domain.CertificateProfile, len(src))
	for id, profile := range src {
		dst[id] = copyCertificateProfile(profile)
	}
	return dst
}

func cloneEnrollments(src map[string]domain.Enrollment) map[string]domain.Enrollment {
	dst := make(map[string]domain.Enrollment, len(src))
	for id, enrollment := range src {
		dst[id] = copyEnrollment(enrollment)
	}
	return dst
}

func cloneCertificates(src map[string]domain.Certificate) map[string]domain.Certificate {
	dst := make(map[string]domain.Certificate, len(src))
	for id, certificate := range src {
		dst[id] = copyCertificate(certificate)
	}
	return dst
}

func cloneRevocations(src map[string]domain.Revocation) map[string]domain.Revocation {
	dst := make(map[string]domain.Revocation, len(src))
	for id, revocation := range src {
		dst[id] = revocation
	}
	return dst
}

func cloneCRLPublications(src map[string]domain.CRLPublication) map[string]domain.CRLPublication {
	dst := make(map[string]domain.CRLPublication, len(src))
	for id, publication := range src {
		dst[id] = publication
	}
	return dst
}

func listRevocationsByIssuer(certificates map[string]domain.Certificate, revocations map[string]domain.Revocation, issuerID string) []domain.RevokedCertificateEntry {
	entries := make([]domain.RevokedCertificateEntry, 0)
	for _, revocation := range revocations {
		certificate, ok := certificates[revocation.CertificateID]
		if !ok || certificate.IssuerID != issuerID || certificate.Status != domain.CertificateRevoked {
			continue
		}
		entries = append(entries, domain.RevokedCertificateEntry{
			CertificateID: certificate.ID,
			SerialNumber:  certificate.SerialNumber,
			RevokedAt:     revocation.RevokedAt,
			Reason:        revocation.Reason,
		})
	}
	return entries
}

func listCRLPublicationsByIssuer(publications map[string]domain.CRLPublication, issuerID string) []domain.CRLPublication {
	result := make([]domain.CRLPublication, 0)
	for _, publication := range publications {
		if publication.IssuerID == issuerID {
			result = append(result, publication)
		}
	}
	return result
}

func listOCSPRespondersByIssuer(responders map[string]domain.OCSPResponder, issuerID string) []domain.OCSPResponder {
	result := make([]domain.OCSPResponder, 0)
	for _, responder := range responders {
		if responder.IssuerID == issuerID {
			result = append(result, responder)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result
}

func activeOCSPResponderByIssuer(responders map[string]domain.OCSPResponder, issuerID string) (domain.OCSPResponder, error) {
	var active domain.OCSPResponder
	found := false
	for _, responder := range responders {
		if responder.IssuerID != issuerID || responder.Status != domain.OCSPResponderActive {
			continue
		}
		if !found || responder.CreatedAt.After(active.CreatedAt) || (responder.CreatedAt.Equal(active.CreatedAt) && responder.ID > active.ID) {
			active = responder
			found = true
		}
	}
	if !found {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	return active, nil
}

func listCertificatesForExpirationScan(certificates map[string]domain.Certificate, now time.Time, warningBefore time.Time, limit int) []domain.Certificate {
	if limit <= 0 {
		return nil
	}
	result := make([]domain.Certificate, 0)
	for _, certificate := range certificates {
		if certificateNeedsExpirationScan(certificate, now, warningBefore) {
			result = append(result, copyCertificate(certificate))
		}
	}
	sort.Slice(result, func(i int, j int) bool {
		if !result[i].NotAfter.Equal(result[j].NotAfter) {
			return result[i].NotAfter.Before(result[j].NotAfter)
		}
		return result[i].ID < result[j].ID
	})
	if len(result) > limit {
		return result[:limit]
	}
	return result
}

func certificateNeedsExpirationScan(certificate domain.Certificate, now time.Time, warningBefore time.Time) bool {
	if (certificate.Status == domain.CertificateValid || certificate.Status == domain.CertificateSuspended) && !certificate.NotAfter.After(now) {
		return true
	}
	return certificate.Status == domain.CertificateValid &&
		certificate.NotAfter.After(now) &&
		!certificate.NotAfter.After(warningBefore) &&
		certificate.RenewalNotifiedAt.IsZero()
}

func latestCRLPublicationByIssuer(publications map[string]domain.CRLPublication, issuerID string) (domain.CRLPublication, error) {
	var latest domain.CRLPublication
	found := false
	for _, publication := range publications {
		if publication.IssuerID != issuerID {
			continue
		}
		if !found || publication.CRLNumber > latest.CRLNumber || publication.CreatedAt.After(latest.CreatedAt) {
			latest = publication
			found = true
		}
	}
	if !found {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	return latest, nil
}

func cloneAuditEvents(src []domain.AuditEvent) []domain.AuditEvent {
	dst := make([]domain.AuditEvent, len(src))
	copy(dst, src)
	return dst
}

func cloneOutboxMessages(src map[string]domain.OutboxMessage) map[string]domain.OutboxMessage {
	dst := make(map[string]domain.OutboxMessage, len(src))
	for id, message := range src {
		dst[id] = message
	}
	return dst
}

func cloneJobAttempts(src map[string]domain.JobAttempt) map[string]domain.JobAttempt {
	dst := make(map[string]domain.JobAttempt, len(src))
	for id, attempt := range src {
		dst[id] = attempt
	}
	return dst
}
