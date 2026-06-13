package store

import (
	"context"
	"sync"

	"github.com/modern-pki/modern-pki/service/internal/domain"
)

type MemoryStore struct {
	mu sync.RWMutex

	identities   map[string]domain.Identity
	issuers      map[string]domain.Issuer
	profiles     map[string]domain.CertificateProfile
	enrollments  map[string]domain.Enrollment
	certificates map[string]domain.Certificate
	revocations  map[string]domain.Revocation
	auditEvents  []domain.AuditEvent
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities:   make(map[string]domain.Identity),
		issuers:      make(map[string]domain.Issuer),
		profiles:     make(map[string]domain.CertificateProfile),
		enrollments:  make(map[string]domain.Enrollment),
		certificates: make(map[string]domain.Certificate),
		revocations:  make(map[string]domain.Revocation),
		auditEvents:  make([]domain.AuditEvent, 0),
	}
}

func (s *MemoryStore) WithinTx(ctx context.Context, fn func(Repository) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx := &memoryTx{
		identities:   cloneIdentities(s.identities),
		issuers:      cloneIssuers(s.issuers),
		profiles:     cloneCertificateProfiles(s.profiles),
		enrollments:  cloneEnrollments(s.enrollments),
		certificates: cloneCertificates(s.certificates),
		revocations:  cloneRevocations(s.revocations),
		auditEvents:  cloneAuditEvents(s.auditEvents),
	}
	if err := fn(tx); err != nil {
		return err
	}

	s.identities = tx.identities
	s.issuers = tx.issuers
	s.profiles = tx.profiles
	s.enrollments = tx.enrollments
	s.certificates = tx.certificates
	s.revocations = tx.revocations
	s.auditEvents = tx.auditEvents
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

type memoryTx struct {
	identities   map[string]domain.Identity
	issuers      map[string]domain.Issuer
	profiles     map[string]domain.CertificateProfile
	enrollments  map[string]domain.Enrollment
	certificates map[string]domain.Certificate
	revocations  map[string]domain.Revocation
	auditEvents  []domain.AuditEvent
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

func (tx *memoryTx) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	tx.auditEvents = append(tx.auditEvents, event)
	return nil
}

func (tx *memoryTx) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	events := make([]domain.AuditEvent, len(tx.auditEvents))
	copy(events, tx.auditEvents)
	return events, nil
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

func cloneAuditEvents(src []domain.AuditEvent) []domain.AuditEvent {
	dst := make([]domain.AuditEvent, len(src))
	copy(dst, src)
	return dst
}
