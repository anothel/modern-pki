package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
)

type SQLStore struct {
	db *sql.DB
}

type sqlExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type sqlScanner interface {
	Scan(dest ...any) error
}

type sqlRepository struct {
	exec sqlExecutor
}

var _ Repository = (*SQLStore)(nil)
var _ Repository = sqlRepository{}

func NewSQLStore(db *sql.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) WithinTx(ctx context.Context, fn func(Repository) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	repo := sqlRepository{exec: tx}
	if err := fn(repo); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLStore) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	return s.repository().CreateIdentity(ctx, identity)
}

func (s *SQLStore) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	return s.repository().GetIdentity(ctx, id)
}

func (s *SQLStore) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	return s.repository().ListIdentities(ctx)
}

func (s *SQLStore) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	return s.repository().CreateIssuer(ctx, issuer)
}

func (s *SQLStore) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	return s.repository().GetIssuer(ctx, id)
}

func (s *SQLStore) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	return s.repository().ListIssuers(ctx)
}

func (s *SQLStore) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	return s.repository().CreateOCSPResponder(ctx, responder)
}

func (s *SQLStore) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	return s.repository().GetOCSPResponder(ctx, id)
}

func (s *SQLStore) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	return s.repository().ListOCSPRespondersByIssuer(ctx, issuerID)
}

func (s *SQLStore) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	return s.repository().GetActiveOCSPResponderByIssuer(ctx, issuerID)
}

func (s *SQLStore) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	return s.repository().UpdateOCSPResponderIfStatus(ctx, responder, currentStatus)
}

func (s *SQLStore) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	return s.repository().CreateNotificationEndpoint(ctx, endpoint)
}

func (s *SQLStore) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	return s.repository().GetNotificationEndpoint(ctx, id)
}

func (s *SQLStore) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	return s.repository().ListNotificationEndpoints(ctx)
}

func (s *SQLStore) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	return s.repository().UpdateNotificationEndpointIfStatus(ctx, endpoint, currentStatus)
}

func (s *SQLStore) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	return s.repository().CreateCertificateProfile(ctx, profile)
}

func (s *SQLStore) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	return s.repository().GetCertificateProfile(ctx, id)
}

func (s *SQLStore) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	return s.repository().ListCertificateProfiles(ctx)
}

func (s *SQLStore) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	return s.repository().CreateEnrollment(ctx, enrollment)
}

func (s *SQLStore) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	return s.repository().GetEnrollment(ctx, id)
}

func (s *SQLStore) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	return s.repository().ListEnrollments(ctx)
}

func (s *SQLStore) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	return s.repository().UpdateEnrollment(ctx, enrollment)
}

func (s *SQLStore) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	return s.repository().UpdateEnrollmentIfStatus(ctx, enrollment, currentStatus)
}

func (s *SQLStore) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	return s.repository().CreateCertificate(ctx, certificate)
}

func (s *SQLStore) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	return s.repository().GetCertificate(ctx, id)
}

func (s *SQLStore) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	return s.repository().ListCertificates(ctx)
}

func (s *SQLStore) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesForExpirationScan(ctx, now, warningBefore, limit)
}

func (s *SQLStore) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	return s.repository().UpdateCertificate(ctx, certificate)
}

func (s *SQLStore) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	return s.repository().UpdateCertificateIfStatus(ctx, certificate, currentStatus)
}

func (s *SQLStore) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	return s.repository().CreateRevocation(ctx, revocation)
}

func (s *SQLStore) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	return s.repository().ListRevocationsByIssuer(ctx, issuerID)
}

func (s *SQLStore) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	return s.repository().CreateCRLPublication(ctx, publication)
}

func (s *SQLStore) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	return s.repository().GetCRLPublication(ctx, id)
}

func (s *SQLStore) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	return s.repository().GetLatestCRLPublicationByIssuer(ctx, issuerID)
}

func (s *SQLStore) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	return s.repository().ListCRLPublicationsByIssuer(ctx, issuerID)
}

func (s *SQLStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return s.repository().CreateAuditEvent(ctx, event)
}

func (s *SQLStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEvents(ctx)
}

func (s *SQLStore) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	return s.repository().CreateOutboxMessage(ctx, message)
}

func (s *SQLStore) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	return s.repository().GetOutboxMessage(ctx, id)
}

func (s *SQLStore) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	return s.repository().ListOutboxMessages(ctx, status)
}

func (s *SQLStore) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	return s.repository().ListDueOutboxMessages(ctx, now, limit)
}

func (s *SQLStore) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	return s.repository().UpdateOutboxMessageStatusIfStatus(ctx, message, currentStatus)
}

func (s *SQLStore) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	return s.repository().CreateJobAttempt(ctx, attempt)
}

func (s *SQLStore) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	return s.repository().ListJobAttemptsByOutboxMessage(ctx, outboxMessageID)
}

func (s *SQLStore) repository() sqlRepository {
	return sqlRepository{exec: s.db}
}

func (r sqlRepository) WithinTx(ctx context.Context, fn func(Repository) error) error {
	return fn(r)
}

func (r sqlRepository) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO identities (
	id, type, name, external_id, status, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7
)`,
		identity.ID,
		string(identity.Type),
		identity.Name,
		identity.ExternalID,
		string(identity.Status),
		formatSQLTime(identity.CreatedAt),
		formatSQLTime(identity.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	identity, err := scanIdentity(r.exec.QueryRowContext(ctx, `
SELECT id, type, name, external_id, status, created_at, updated_at
FROM identities
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Identity{}, domain.ErrIdentityNotFound
	}
	if err != nil {
		return domain.Identity{}, err
	}
	return identity, nil
}

func (r sqlRepository) ListIdentities(ctx context.Context) ([]domain.Identity, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, type, name, external_id, status, created_at, updated_at
FROM identities
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	identities := make([]domain.Identity, 0)
	for rows.Next() {
		identity, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return identities, nil
}

func (r sqlRepository) CreateIssuer(ctx context.Context, issuer domain.Issuer) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO issuers (
	id, name, kind, status, certificate_pem, key_ref, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		issuer.ID,
		issuer.Name,
		string(issuer.Kind),
		string(issuer.Status),
		issuer.CertificatePEM,
		issuer.KeyRef,
		formatSQLTime(issuer.CreatedAt),
		formatSQLTime(issuer.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	issuer, err := scanIssuer(r.exec.QueryRowContext(ctx, `
SELECT id, name, kind, status, certificate_pem, key_ref, created_at, updated_at
FROM issuers
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Issuer{}, domain.ErrIssuerNotFound
	}
	if err != nil {
		return domain.Issuer{}, err
	}
	return issuer, nil
}

func (r sqlRepository) ListIssuers(ctx context.Context) ([]domain.Issuer, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, kind, status, certificate_pem, key_ref, created_at, updated_at
FROM issuers
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	issuers := make([]domain.Issuer, 0)
	for rows.Next() {
		issuer, err := scanIssuer(rows)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, issuer)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return issuers, nil
}

func (r sqlRepository) CreateOCSPResponder(ctx context.Context, responder domain.OCSPResponder) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO ocsp_responders (
	id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		responder.ID,
		responder.IssuerID,
		responder.Name,
		string(responder.Status),
		responder.CertificatePEM,
		responder.KeyRef,
		formatSQLTime(responder.CreatedAt),
		formatSQLTime(responder.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetOCSPResponder(ctx context.Context, id string) (domain.OCSPResponder, error) {
	responder, err := scanOCSPResponder(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	return responder, nil
}

func (r sqlRepository) ListOCSPRespondersByIssuer(ctx context.Context, issuerID string) ([]domain.OCSPResponder, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE issuer_id = $1
ORDER BY created_at, id`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	responders := make([]domain.OCSPResponder, 0)
	for rows.Next() {
		responder, err := scanOCSPResponder(rows)
		if err != nil {
			return nil, err
		}
		responders = append(responders, responder)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return responders, nil
}

func (r sqlRepository) GetActiveOCSPResponderByIssuer(ctx context.Context, issuerID string) (domain.OCSPResponder, error) {
	responder, err := scanOCSPResponder(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, name, status, certificate_pem, key_ref, created_at, updated_at
FROM ocsp_responders
WHERE issuer_id = $1 AND status = $2
ORDER BY created_at DESC, id DESC
LIMIT 1`, issuerID, string(domain.OCSPResponderActive)))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OCSPResponder{}, domain.ErrOCSPResponderNotFound
	}
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	return responder, nil
}

func (r sqlRepository) UpdateOCSPResponderIfStatus(ctx context.Context, responder domain.OCSPResponder, currentStatus domain.OCSPResponderStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE ocsp_responders
SET issuer_id = $1,
	name = $2,
	status = $3,
	certificate_pem = $4,
	key_ref = $5,
	created_at = $6,
	updated_at = $7
WHERE id = $8 AND status = $9`,
		responder.IssuerID,
		responder.Name,
		string(responder.Status),
		responder.CertificatePEM,
		responder.KeyRef,
		formatSQLTime(responder.CreatedAt),
		formatSQLTime(responder.UpdatedAt),
		responder.ID,
		string(currentStatus),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetOCSPResponder(ctx, responder.ID); errors.Is(err, domain.ErrOCSPResponderNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateNotificationEndpoint(ctx context.Context, endpoint domain.NotificationEndpoint) error {
	eventTypes, err := marshalStringSlice(endpoint.EventTypes)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO notification_endpoints (
	id, name, type, status, url, event_types, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		endpoint.ID,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		eventTypes,
		formatSQLTime(endpoint.CreatedAt),
		formatSQLTime(endpoint.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	endpoint, err := scanNotificationEndpoint(r.exec.QueryRowContext(ctx, `
SELECT id, name, type, status, url, event_types, created_at, updated_at
FROM notification_endpoints
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.NotificationEndpoint{}, domain.ErrNotificationEndpointNotFound
	}
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	return endpoint, nil
}

func (r sqlRepository) ListNotificationEndpoints(ctx context.Context) ([]domain.NotificationEndpoint, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, type, status, url, event_types, created_at, updated_at
FROM notification_endpoints
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	endpoints := make([]domain.NotificationEndpoint, 0)
	for rows.Next() {
		endpoint, err := scanNotificationEndpoint(rows)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return endpoints, nil
}

func (r sqlRepository) UpdateNotificationEndpointIfStatus(ctx context.Context, endpoint domain.NotificationEndpoint, currentStatus domain.NotificationEndpointStatus) error {
	eventTypes, err := marshalStringSlice(endpoint.EventTypes)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE notification_endpoints
SET name = $1,
	type = $2,
	status = $3,
	url = $4,
	event_types = $5,
	created_at = $6,
	updated_at = $7
WHERE id = $8 AND status = $9`,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		eventTypes,
		formatSQLTime(endpoint.CreatedAt),
		formatSQLTime(endpoint.UpdatedAt),
		endpoint.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetNotificationEndpoint(ctx, endpoint.ID); errors.Is(err, domain.ErrNotificationEndpointNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error {
	allowedDNSPatterns, err := marshalStringSlice(profile.AllowedDNSPatterns)
	if err != nil {
		return err
	}
	allowedIPRanges, err := marshalStringSlice(profile.AllowedIPRanges)
	if err != nil {
		return err
	}
	keyUsage, err := marshalJSON(profile.KeyUsage)
	if err != nil {
		return err
	}
	extendedKeyUsage, err := marshalJSON(profile.ExtendedKeyUsage)
	if err != nil {
		return err
	}
	basicConstraints, err := marshalJSON(profile.BasicConstraints)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO certificate_profiles (
	id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, key_usage, extended_key_usage,
	basic_constraints, subject_key_identifier, authority_key_identifier, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
)`,
		profile.ID,
		profile.Name,
		profile.Description,
		profile.IssuerID,
		profile.ValidityPeriodSeconds,
		profile.SubjectTemplate,
		allowedDNSPatterns,
		allowedIPRanges,
		keyUsage,
		extendedKeyUsage,
		basicConstraints,
		profile.SubjectKeyIdentifier,
		profile.AuthorityKeyIdentifier,
		formatSQLTime(profile.CreatedAt),
		formatSQLTime(profile.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	profile, err := scanCertificateProfile(r.exec.QueryRowContext(ctx, `
SELECT id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, key_usage, extended_key_usage,
	basic_constraints, subject_key_identifier, authority_key_identifier, created_at, updated_at
FROM certificate_profiles
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CertificateProfile{}, domain.ErrCertificateProfileNotFound
	}
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	return profile, nil
}

func (r sqlRepository) ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, key_usage, extended_key_usage,
	basic_constraints, subject_key_identifier, authority_key_identifier, created_at, updated_at
FROM certificate_profiles
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	profiles := make([]domain.CertificateProfile, 0)
	for rows.Next() {
		profile, err := scanCertificateProfile(rows)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return profiles, nil
}

func (r sqlRepository) CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	requestedDNSNames, err := marshalStringSlice(enrollment.RequestedDNSNames)
	if err != nil {
		return err
	}
	requestedIPAddresses, err := marshalStringSlice(enrollment.RequestedIPAddresses)
	if err != nil {
		return err
	}
	csrDNSNames, err := marshalStringSlice(enrollment.CSRDNSNames)
	if err != nil {
		return err
	}
	csrIPAddresses, err := marshalStringSlice(enrollment.CSRIPAddresses)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO enrollments (
	id, identity_id, issuer_id, certificate_profile_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		enrollment.ID,
		enrollment.IdentityID,
		enrollment.IssuerID,
		enrollment.CertificateProfileID,
		enrollment.CSRPEM,
		string(enrollment.Status),
		enrollment.RequestedSubject,
		requestedDNSNames,
		requestedIPAddresses,
		csrDNSNames,
		csrIPAddresses,
		formatSQLTime(enrollment.RequestedNotAfter),
		enrollment.ApprovedBy,
		formatNullableSQLTime(enrollment.ApprovedAt),
		formatSQLTime(enrollment.CreatedAt),
		formatSQLTime(enrollment.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error) {
	enrollment, err := scanEnrollment(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, certificate_profile_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Enrollment{}, domain.ErrEnrollmentNotFound
	}
	if err != nil {
		return domain.Enrollment{}, err
	}
	return enrollment, nil
}

func (r sqlRepository) ListEnrollments(ctx context.Context) ([]domain.Enrollment, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, certificate_profile_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	enrollments := make([]domain.Enrollment, 0)
	for rows.Next() {
		enrollment, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		enrollments = append(enrollments, enrollment)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return enrollments, nil
}

func (r sqlRepository) UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error {
	result, err := r.updateEnrollment(ctx, enrollment, "", false)
	if err != nil {
		return err
	}
	return requireRowsAffected(result, domain.ErrEnrollmentNotFound)
}

func (r sqlRepository) UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error {
	result, err := r.updateEnrollment(ctx, enrollment, currentStatus, true)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetEnrollment(ctx, enrollment.ID); errors.Is(err, domain.ErrEnrollmentNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) updateEnrollment(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus, requireStatus bool) (sql.Result, error) {
	requestedDNSNames, err := marshalStringSlice(enrollment.RequestedDNSNames)
	if err != nil {
		return nil, err
	}
	requestedIPAddresses, err := marshalStringSlice(enrollment.RequestedIPAddresses)
	if err != nil {
		return nil, err
	}
	csrDNSNames, err := marshalStringSlice(enrollment.CSRDNSNames)
	if err != nil {
		return nil, err
	}
	csrIPAddresses, err := marshalStringSlice(enrollment.CSRIPAddresses)
	if err != nil {
		return nil, err
	}

	query := `
UPDATE enrollments
SET identity_id = $1,
	issuer_id = $2,
	certificate_profile_id = $3,
	csr_pem = $4,
	status = $5,
	requested_subject = $6,
	requested_dns_names = $7,
	requested_ip_addresses = $8,
	csr_dns_names = $9,
	csr_ip_addresses = $10,
	requested_not_after = $11,
	approved_by = $12,
	approved_at = $13,
	created_at = $14,
	updated_at = $15
WHERE id = $16`
	args := []any{
		enrollment.IdentityID,
		enrollment.IssuerID,
		enrollment.CertificateProfileID,
		enrollment.CSRPEM,
		string(enrollment.Status),
		enrollment.RequestedSubject,
		requestedDNSNames,
		requestedIPAddresses,
		csrDNSNames,
		csrIPAddresses,
		formatSQLTime(enrollment.RequestedNotAfter),
		enrollment.ApprovedBy,
		formatNullableSQLTime(enrollment.ApprovedAt),
		formatSQLTime(enrollment.CreatedAt),
		formatSQLTime(enrollment.UpdatedAt),
		enrollment.ID,
	}
	if requireStatus {
		query += `
AND status = $17`
		args = append(args, string(currentStatus))
	}
	return r.exec.ExecContext(ctx, query, args...)
}

func (r sqlRepository) CreateCertificate(ctx context.Context, certificate domain.Certificate) error {
	dnsNames, err := marshalStringSlice(certificate.DNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(certificate.IPAddresses)
	if err != nil {
		return err
	}

	_, err = r.exec.ExecContext(ctx, `
INSERT INTO certificates (
	id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		certificate.ID,
		certificate.IdentityID,
		certificate.IssuerID,
		certificate.EnrollmentID,
		certificate.CertificateProfileID,
		certificate.SerialNumber,
		certificate.Subject,
		dnsNames,
		ipAddresses,
		formatSQLTime(certificate.NotBefore),
		formatSQLTime(certificate.NotAfter),
		string(certificate.Status),
		certificate.CertificatePEM,
		formatNullableSQLTime(certificate.RenewalNotifiedAt),
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	certificate, err := scanCertificate(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Certificate{}, domain.ErrCertificateNotFound
	}
	if err != nil {
		return domain.Certificate{}, err
	}
	return certificate, nil
}

func (r sqlRepository) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) ListCertificatesForExpirationScan(ctx context.Context, now time.Time, warningBefore time.Time, limit int) ([]domain.Certificate, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE (
	status IN ($1, $2) AND not_after <= $3
) OR (
	status = $1 AND not_after > $3 AND not_after <= $4 AND renewal_notified_at IS NULL
)
ORDER BY not_after, id
LIMIT $5`,
		string(domain.CertificateValid),
		string(domain.CertificateSuspended),
		formatSQLTime(now),
		formatSQLTime(warningBefore),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	certificates := make([]domain.Certificate, 0)
	for rows.Next() {
		certificate, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return certificates, nil
}

func (r sqlRepository) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	result, err := r.updateCertificate(ctx, certificate, "", false)
	if err != nil {
		return err
	}
	return requireRowsAffected(result, domain.ErrCertificateNotFound)
}

func (r sqlRepository) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	result, err := r.updateCertificate(ctx, certificate, currentStatus, true)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := r.GetCertificate(ctx, certificate.ID); errors.Is(err, domain.ErrCertificateNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) updateCertificate(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus, requireStatus bool) (sql.Result, error) {
	dnsNames, err := marshalStringSlice(certificate.DNSNames)
	if err != nil {
		return nil, err
	}
	ipAddresses, err := marshalStringSlice(certificate.IPAddresses)
	if err != nil {
		return nil, err
	}

	query := `
UPDATE certificates
SET identity_id = $1,
	issuer_id = $2,
	enrollment_id = $3,
	certificate_profile_id = $4,
	serial_number = $5,
	subject = $6,
	dns_names = $7,
	ip_addresses = $8,
	not_before = $9,
	not_after = $10,
	status = $11,
	certificate_pem = $12,
	renewal_notified_at = $13,
	created_at = $14,
	updated_at = $15
WHERE id = $16`
	args := []any{
		certificate.IdentityID,
		certificate.IssuerID,
		certificate.EnrollmentID,
		certificate.CertificateProfileID,
		certificate.SerialNumber,
		certificate.Subject,
		dnsNames,
		ipAddresses,
		formatSQLTime(certificate.NotBefore),
		formatSQLTime(certificate.NotAfter),
		string(certificate.Status),
		certificate.CertificatePEM,
		formatNullableSQLTime(certificate.RenewalNotifiedAt),
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
		certificate.ID,
	}
	if requireStatus {
		query += `
AND status = $17`
		args = append(args, string(currentStatus))
	}
	return r.exec.ExecContext(ctx, query, args...)
}

func (r sqlRepository) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO revocations (
	id, certificate_id, reason, revoked_by, revoked_at, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6
)`,
		revocation.ID,
		revocation.CertificateID,
		string(revocation.Reason),
		revocation.RevokedBy,
		formatSQLTime(revocation.RevokedAt),
		formatSQLTime(revocation.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListRevocationsByIssuer(ctx context.Context, issuerID string) ([]domain.RevokedCertificateEntry, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT c.id, c.serial_number, r.revoked_at, r.reason
FROM revocations r
JOIN certificates c ON c.id = r.certificate_id
WHERE c.issuer_id = $1 AND c.status = $2
ORDER BY r.revoked_at, c.serial_number`, issuerID, string(domain.CertificateRevoked))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := make([]domain.RevokedCertificateEntry, 0)
	for rows.Next() {
		entry, err := scanRevokedCertificateEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func (r sqlRepository) CreateCRLPublication(ctx context.Context, publication domain.CRLPublication) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO crl_publications (
	id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)`,
		publication.ID,
		publication.IssuerID,
		publication.DistributionPoint,
		publication.CRLNumber,
		formatSQLTime(publication.ThisUpdate),
		formatSQLTime(publication.NextUpdate),
		string(publication.Status),
		publication.CRLPEM,
		formatSQLTime(publication.CreatedAt),
		formatSQLTime(publication.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCRLPublication(ctx context.Context, id string) (domain.CRLPublication, error) {
	publication, err := scanCRLPublication(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	if err != nil {
		return domain.CRLPublication{}, err
	}
	return publication, nil
}

func (r sqlRepository) GetLatestCRLPublicationByIssuer(ctx context.Context, issuerID string) (domain.CRLPublication, error) {
	publication, err := scanCRLPublication(r.exec.QueryRowContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE issuer_id = $1
ORDER BY crl_number DESC, created_at DESC, id DESC
LIMIT 1`, issuerID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.CRLPublication{}, domain.ErrCRLPublicationNotFound
	}
	if err != nil {
		return domain.CRLPublication{}, err
	}
	return publication, nil
}

func (r sqlRepository) ListCRLPublicationsByIssuer(ctx context.Context, issuerID string) ([]domain.CRLPublication, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, issuer_id, distribution_point, crl_number, this_update, next_update, status, crl_pem, created_at, updated_at
FROM crl_publications
WHERE issuer_id = $1
ORDER BY crl_number, created_at, id`, issuerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	publications := make([]domain.CRLPublication, 0)
	for rows.Next() {
		publication, err := scanCRLPublication(rows)
		if err != nil {
			return nil, err
		}
		publications = append(publications, publication)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return publications, nil
}

func (r sqlRepository) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO audit_events (
	id, actor, action, resource_type, resource_id, metadata_json, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7
)`,
		event.ID,
		event.Actor,
		event.Action,
		event.ResourceType,
		event.ResourceID,
		event.MetadataJSON,
		formatSQLTime(event.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, actor, action, resource_type, resource_id, metadata_json, created_at
FROM audit_events
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	events := make([]domain.AuditEvent, 0)
	for rows.Next() {
		event, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (r sqlRepository) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO outbox_messages (
	id, type, payload_json, status, available_at, attempt_count, max_attempts, last_error, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)`,
		message.ID,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetOutboxMessage(ctx context.Context, id string) (domain.OutboxMessage, error) {
	message, err := scanOutboxMessage(r.exec.QueryRowContext(ctx, `
SELECT id, type, payload_json, status, available_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.OutboxMessage{}, domain.ErrOutboxMessageNotFound
	}
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	return message, nil
}

func (r sqlRepository) ListOutboxMessages(ctx context.Context, status domain.OutboxMessageStatus) ([]domain.OutboxMessage, error) {
	query := `
SELECT id, type, payload_json, status, available_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages`
	args := []any{}
	if status != "" {
		query += " WHERE status = $1"
		args = append(args, string(status))
	}
	query += " ORDER BY created_at, id"

	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]domain.OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutboxMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r sqlRepository) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	if limit <= 0 {
		return nil, nil
	}

	rows, err := r.exec.QueryContext(ctx, `
SELECT id, type, payload_json, status, available_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE status = $1 AND available_at <= $2
ORDER BY available_at, created_at, id
LIMIT $3`, string(domain.OutboxPending), formatSQLTime(now), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	messages := make([]domain.OutboxMessage, 0)
	for rows.Next() {
		message, err := scanOutboxMessage(rows)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return messages, nil
}

func (r sqlRepository) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE outbox_messages
SET type = $1,
	payload_json = $2,
	status = $3,
	available_at = $4,
	attempt_count = $5,
	max_attempts = $6,
	last_error = $7,
	created_at = $8,
	updated_at = $9
WHERE id = $10 AND status = $11`,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
		message.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected != 0 {
		return nil
	}
	if _, err := scanOutboxMessage(r.exec.QueryRowContext(ctx, `
SELECT id, type, payload_json, status, available_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, message.ID)); errors.Is(err, sql.ErrNoRows) {
		return domain.ErrOutboxMessageNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO job_attempts (
	id, outbox_message_id, status, error, started_at, finished_at, created_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7
)`,
		attempt.ID,
		attempt.OutboxMessageID,
		string(attempt.Status),
		attempt.Error,
		formatSQLTime(attempt.StartedAt),
		formatSQLTime(attempt.FinishedAt),
		formatSQLTime(attempt.CreatedAt),
	)
	return err
}

func (r sqlRepository) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, outbox_message_id, status, error, started_at, finished_at, created_at
FROM job_attempts
WHERE outbox_message_id = $1
ORDER BY created_at, id`, outboxMessageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	attempts := make([]domain.JobAttempt, 0)
	for rows.Next() {
		attempt, err := scanJobAttempt(rows)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return attempts, nil
}

func scanIdentity(scanner sqlScanner) (domain.Identity, error) {
	var identity domain.Identity
	var identityType string
	var status string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&identity.ID,
		&identityType,
		&identity.Name,
		&identity.ExternalID,
		&status,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Identity{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Identity{}, err
	}

	identity.Type = domain.IdentityType(identityType)
	identity.Status = domain.IdentityStatus(status)
	identity.CreatedAt = parsedCreatedAt
	identity.UpdatedAt = parsedUpdatedAt
	return identity, nil
}

func scanIssuer(scanner sqlScanner) (domain.Issuer, error) {
	var issuer domain.Issuer
	var kind string
	var status string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&issuer.ID,
		&issuer.Name,
		&kind,
		&status,
		&issuer.CertificatePEM,
		&issuer.KeyRef,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Issuer{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Issuer{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Issuer{}, err
	}

	issuer.Kind = domain.IssuerKind(kind)
	issuer.Status = domain.IssuerStatus(status)
	issuer.CreatedAt = parsedCreatedAt
	issuer.UpdatedAt = parsedUpdatedAt
	return issuer, nil
}

func scanOCSPResponder(scanner sqlScanner) (domain.OCSPResponder, error) {
	var responder domain.OCSPResponder
	var status string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&responder.ID,
		&responder.IssuerID,
		&responder.Name,
		&status,
		&responder.CertificatePEM,
		&responder.KeyRef,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.OCSPResponder{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.OCSPResponder{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.OCSPResponder{}, err
	}

	responder.Status = domain.OCSPResponderStatus(status)
	responder.CreatedAt = parsedCreatedAt
	responder.UpdatedAt = parsedUpdatedAt
	return responder, nil
}

func scanNotificationEndpoint(scanner sqlScanner) (domain.NotificationEndpoint, error) {
	var endpoint domain.NotificationEndpoint
	var endpointType string
	var status string
	var eventTypes string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&endpoint.ID,
		&endpoint.Name,
		&endpointType,
		&status,
		&endpoint.URL,
		&eventTypes,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.NotificationEndpoint{}, err
	}

	parsedEventTypes, err := unmarshalStringSlice(eventTypes)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.NotificationEndpoint{}, err
	}

	endpoint.Type = domain.NotificationEndpointType(endpointType)
	endpoint.Status = domain.NotificationEndpointStatus(status)
	endpoint.EventTypes = parsedEventTypes
	endpoint.CreatedAt = parsedCreatedAt
	endpoint.UpdatedAt = parsedUpdatedAt
	return endpoint, nil
}

func scanCertificateProfile(scanner sqlScanner) (domain.CertificateProfile, error) {
	var profile domain.CertificateProfile
	var allowedDNSPatterns string
	var allowedIPRanges string
	var keyUsage string
	var extendedKeyUsage string
	var basicConstraints string
	var subjectKeyIdentifier bool
	var authorityKeyIdentifier bool
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&profile.ID,
		&profile.Name,
		&profile.Description,
		&profile.IssuerID,
		&profile.ValidityPeriodSeconds,
		&profile.SubjectTemplate,
		&allowedDNSPatterns,
		&allowedIPRanges,
		&keyUsage,
		&extendedKeyUsage,
		&basicConstraints,
		&subjectKeyIdentifier,
		&authorityKeyIdentifier,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.CertificateProfile{}, err
	}

	parsedAllowedDNSPatterns, err := unmarshalStringSlice(allowedDNSPatterns)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedAllowedIPRanges, err := unmarshalStringSlice(allowedIPRanges)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalJSON(keyUsage, &profile.KeyUsage); err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalJSON(extendedKeyUsage, &profile.ExtendedKeyUsage); err != nil {
		return domain.CertificateProfile{}, err
	}
	if err := unmarshalBasicConstraintsPolicy(basicConstraints, &profile.BasicConstraints); err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.CertificateProfile{}, err
	}

	profile.AllowedDNSPatterns = parsedAllowedDNSPatterns
	profile.AllowedIPRanges = parsedAllowedIPRanges
	profile.SubjectKeyIdentifier = subjectKeyIdentifier
	profile.AuthorityKeyIdentifier = authorityKeyIdentifier
	profile.CreatedAt = parsedCreatedAt
	profile.UpdatedAt = parsedUpdatedAt
	return profile, nil
}

func scanEnrollment(scanner sqlScanner) (domain.Enrollment, error) {
	var enrollment domain.Enrollment
	var status string
	var requestedDNSNames string
	var requestedIPAddresses string
	var csrDNSNames string
	var csrIPAddresses string
	var requestedNotAfter any
	var approvedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&enrollment.ID,
		&enrollment.IdentityID,
		&enrollment.IssuerID,
		&enrollment.CertificateProfileID,
		&enrollment.CSRPEM,
		&status,
		&enrollment.RequestedSubject,
		&requestedDNSNames,
		&requestedIPAddresses,
		&csrDNSNames,
		&csrIPAddresses,
		&requestedNotAfter,
		&enrollment.ApprovedBy,
		&approvedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Enrollment{}, err
	}

	dnsNames, err := unmarshalStringSlice(requestedDNSNames)
	if err != nil {
		return domain.Enrollment{}, err
	}
	ipAddresses, err := unmarshalStringSlice(requestedIPAddresses)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCSRDNSNames, err := unmarshalStringSlice(csrDNSNames)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCSRIPAddresses, err := unmarshalStringSlice(csrIPAddresses)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedRequestedNotAfter, err := parseSQLTime(requestedNotAfter)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedApprovedAt, err := parseSQLTime(approvedAt)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Enrollment{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Enrollment{}, err
	}

	enrollment.Status = domain.EnrollmentStatus(status)
	enrollment.RequestedDNSNames = dnsNames
	enrollment.RequestedIPAddresses = ipAddresses
	enrollment.CSRDNSNames = parsedCSRDNSNames
	enrollment.CSRIPAddresses = parsedCSRIPAddresses
	enrollment.RequestedNotAfter = parsedRequestedNotAfter
	enrollment.ApprovedAt = parsedApprovedAt
	enrollment.CreatedAt = parsedCreatedAt
	enrollment.UpdatedAt = parsedUpdatedAt
	return enrollment, nil
}

func scanCertificate(scanner sqlScanner) (domain.Certificate, error) {
	var certificate domain.Certificate
	var status string
	var dnsNames string
	var ipAddresses string
	var notBefore any
	var notAfter any
	var renewalNotifiedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&certificate.ID,
		&certificate.IdentityID,
		&certificate.IssuerID,
		&certificate.EnrollmentID,
		&certificate.CertificateProfileID,
		&certificate.SerialNumber,
		&certificate.Subject,
		&dnsNames,
		&ipAddresses,
		&notBefore,
		&notAfter,
		&status,
		&certificate.CertificatePEM,
		&renewalNotifiedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.Certificate{}, err
	}

	parsedDNSNames, err := unmarshalStringSlice(dnsNames)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedIPAddresses, err := unmarshalStringSlice(ipAddresses)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedNotBefore, err := parseSQLTime(notBefore)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedNotAfter, err := parseSQLTime(notAfter)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedRenewalNotifiedAt, err := parseSQLTime(renewalNotifiedAt)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.Certificate{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.Certificate{}, err
	}

	certificate.DNSNames = parsedDNSNames
	certificate.IPAddresses = parsedIPAddresses
	certificate.NotBefore = parsedNotBefore
	certificate.NotAfter = parsedNotAfter
	certificate.Status = domain.CertificateStatus(status)
	certificate.RenewalNotifiedAt = parsedRenewalNotifiedAt
	certificate.CreatedAt = parsedCreatedAt
	certificate.UpdatedAt = parsedUpdatedAt
	return certificate, nil
}

func scanAuditEvent(scanner sqlScanner) (domain.AuditEvent, error) {
	var event domain.AuditEvent
	var createdAt any

	if err := scanner.Scan(
		&event.ID,
		&event.Actor,
		&event.Action,
		&event.ResourceType,
		&event.ResourceID,
		&event.MetadataJSON,
		&createdAt,
	); err != nil {
		return domain.AuditEvent{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.AuditEvent{}, err
	}

	event.CreatedAt = parsedCreatedAt
	return event, nil
}

func scanOutboxMessage(scanner sqlScanner) (domain.OutboxMessage, error) {
	var message domain.OutboxMessage
	var status string
	var availableAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&message.ID,
		&message.Type,
		&message.PayloadJSON,
		&status,
		&availableAt,
		&message.AttemptCount,
		&message.MaxAttempts,
		&message.LastError,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.OutboxMessage{}, err
	}

	parsedAvailableAt, err := parseSQLTime(availableAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.OutboxMessage{}, err
	}

	message.Status = domain.OutboxMessageStatus(status)
	message.AvailableAt = parsedAvailableAt
	message.CreatedAt = parsedCreatedAt
	message.UpdatedAt = parsedUpdatedAt
	return message, nil
}

func scanJobAttempt(scanner sqlScanner) (domain.JobAttempt, error) {
	var attempt domain.JobAttempt
	var status string
	var startedAt any
	var finishedAt any
	var createdAt any

	if err := scanner.Scan(
		&attempt.ID,
		&attempt.OutboxMessageID,
		&status,
		&attempt.Error,
		&startedAt,
		&finishedAt,
		&createdAt,
	); err != nil {
		return domain.JobAttempt{}, err
	}

	parsedStartedAt, err := parseSQLTime(startedAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}
	parsedFinishedAt, err := parseSQLTime(finishedAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.JobAttempt{}, err
	}

	attempt.Status = domain.JobAttemptStatus(status)
	attempt.StartedAt = parsedStartedAt
	attempt.FinishedAt = parsedFinishedAt
	attempt.CreatedAt = parsedCreatedAt
	return attempt, nil
}

func scanRevokedCertificateEntry(scanner sqlScanner) (domain.RevokedCertificateEntry, error) {
	var entry domain.RevokedCertificateEntry
	var reason string
	var revokedAt any
	if err := scanner.Scan(
		&entry.CertificateID,
		&entry.SerialNumber,
		&revokedAt,
		&reason,
	); err != nil {
		return domain.RevokedCertificateEntry{}, err
	}
	parsedRevokedAt, err := parseSQLTime(revokedAt)
	if err != nil {
		return domain.RevokedCertificateEntry{}, err
	}
	entry.RevokedAt = parsedRevokedAt
	entry.Reason = domain.RevocationReason(reason)
	return entry, nil
}

func scanCRLPublication(scanner sqlScanner) (domain.CRLPublication, error) {
	var publication domain.CRLPublication
	var status string
	var thisUpdate any
	var nextUpdate any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&publication.ID,
		&publication.IssuerID,
		&publication.DistributionPoint,
		&publication.CRLNumber,
		&thisUpdate,
		&nextUpdate,
		&status,
		&publication.CRLPEM,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.CRLPublication{}, err
	}
	parsedThisUpdate, err := parseSQLTime(thisUpdate)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedNextUpdate, err := parseSQLTime(nextUpdate)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.CRLPublication{}, err
	}
	publication.ThisUpdate = parsedThisUpdate
	publication.NextUpdate = parsedNextUpdate
	publication.Status = domain.CRLPublicationStatus(status)
	publication.CreatedAt = parsedCreatedAt
	publication.UpdatedAt = parsedUpdatedAt
	return publication, nil
}

func marshalStringSlice(values []string) (string, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func marshalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func unmarshalJSON(data string, value any) error {
	if data == "" {
		return nil
	}
	return json.Unmarshal([]byte(data), value)
}

func unmarshalBasicConstraintsPolicy(data string, value *domain.BasicConstraintsPolicy) error {
	if data == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(data), value); err != nil {
		return err
	}
	if !value.CA && value.MaxPathLen != nil && *value.MaxPathLen == 0 {
		value.MaxPathLen = nil
	}
	return nil
}

func unmarshalStringSlice(data string) ([]string, error) {
	if data == "" {
		return nil, nil
	}

	var values []string
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil, err
	}
	return values, nil
}

const sqlTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatSQLTime(value time.Time) string {
	return value.UTC().Format(sqlTimeLayout)
}

func formatNullableSQLTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return formatSQLTime(value)
}

func parseSQLTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case nil:
		return time.Time{}, nil
	case time.Time:
		if v.IsZero() {
			return time.Time{}, nil
		}
		return v, nil
	case string:
		return parseSQLTimeString(v)
	case []byte:
		return parseSQLTimeString(string(v))
	default:
		return time.Time{}, fmt.Errorf("unsupported SQL time value %T", value)
	}
}

func parseSQLTimeString(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	parsed, err := time.Parse(sqlTimeLayout, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return time.Time{}, err
		}
	}
	if parsed.IsZero() {
		return time.Time{}, nil
	}
	return parsed, nil
}

func requireRowsAffected(result sql.Result, missingErr error) error {
	rowsAffected, err := affectedRows(result)
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return missingErr
	}
	return nil
}

func affectedRows(result sql.Result) (int64, error) {
	return result.RowsAffected()
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint failed") ||
		strings.Contains(message, "duplicate key value violates unique constraint")
}
