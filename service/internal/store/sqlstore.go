package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

func (s *SQLStore) UpdateCertificate(ctx context.Context, certificate domain.Certificate) error {
	return s.repository().UpdateCertificate(ctx, certificate)
}

func (s *SQLStore) UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error {
	return s.repository().UpdateCertificateIfStatus(ctx, certificate, currentStatus)
}

func (s *SQLStore) CreateRevocation(ctx context.Context, revocation domain.Revocation) error {
	return s.repository().CreateRevocation(ctx, revocation)
}

func (s *SQLStore) CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error {
	return s.repository().CreateAuditEvent(ctx, event)
}

func (s *SQLStore) ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEvents(ctx)
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
	created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
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
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCertificate(ctx context.Context, id string) (domain.Certificate, error) {
	certificate, err := scanCertificate(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	created_at, updated_at
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
	created_at, updated_at
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
	created_at = $13,
	updated_at = $14
WHERE id = $15`
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
		formatSQLTime(certificate.CreatedAt),
		formatSQLTime(certificate.UpdatedAt),
		certificate.ID,
	}
	if requireStatus {
		query += `
AND status = $16`
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
