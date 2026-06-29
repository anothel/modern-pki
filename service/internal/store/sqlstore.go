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

func (s *SQLStore) ListIdentitiesQuery(ctx context.Context, query IdentityQuery) ([]domain.Identity, error) {
	return s.repository().ListIdentitiesQuery(ctx, query)
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

func (s *SQLStore) ListEnrollmentsQuery(ctx context.Context, query EnrollmentQuery) ([]domain.Enrollment, error) {
	return s.repository().ListEnrollmentsQuery(ctx, query)
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

func (s *SQLStore) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	return s.repository().GetCertificateByEnrollmentID(ctx, enrollmentID)
}

func (s *SQLStore) ListCertificates(ctx context.Context) ([]domain.Certificate, error) {
	return s.repository().ListCertificates(ctx)
}

func (s *SQLStore) ListCertificatesQuery(ctx context.Context, query CertificateQuery) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesQuery(ctx, query)
}

func (s *SQLStore) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	return s.repository().ListCertificateInventory(ctx, filter)
}

func (s *SQLStore) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	return s.repository().ListCertificatesExpiringWithin(ctx, now, cutoff, limit, offset)
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

func (s *SQLStore) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	return s.repository().CreateIssuanceAttempt(ctx, attempt)
}

func (s *SQLStore) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	return s.repository().GetIssuanceAttempt(ctx, enrollmentID)
}

func (s *SQLStore) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	return s.repository().UpdateIssuanceAttemptIfCurrent(ctx, attempt, current)
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

func (s *SQLStore) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	return s.repository().ListAuditEventsQuery(ctx, query)
}

func (s *SQLStore) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	return s.repository().DeleteAuditEventsBefore(ctx, before)
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

func (s *SQLStore) ListOutboxMessagesQuery(ctx context.Context, query OutboxMessageQuery) ([]domain.OutboxMessage, error) {
	return s.repository().ListOutboxMessagesQuery(ctx, query)
}

func (s *SQLStore) ListDueOutboxMessages(ctx context.Context, now time.Time, limit int) ([]domain.OutboxMessage, error) {
	return s.repository().ListDueOutboxMessages(ctx, now, limit)
}

func (s *SQLStore) UpdateOutboxMessageStatusIfStatus(ctx context.Context, message domain.OutboxMessage, currentStatus domain.OutboxMessageStatus) error {
	return s.repository().UpdateOutboxMessageStatusIfStatus(ctx, message, currentStatus)
}

func (s *SQLStore) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	return s.repository().UpdateOutboxMessageIfCurrent(ctx, message, current)
}

func (s *SQLStore) CreateJobAttempt(ctx context.Context, attempt domain.JobAttempt) error {
	return s.repository().CreateJobAttempt(ctx, attempt)
}

func (s *SQLStore) ListJobAttemptsByOutboxMessage(ctx context.Context, outboxMessageID string) ([]domain.JobAttempt, error) {
	return s.repository().ListJobAttemptsByOutboxMessage(ctx, outboxMessageID)
}

func (s *SQLStore) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	return s.repository().GetWebhookDelivery(ctx, outboxMessageID, endpointID)
}

func (s *SQLStore) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	return s.repository().UpsertWebhookDelivery(ctx, delivery)
}

func (s *SQLStore) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	return s.repository().CreateAPIKey(ctx, key)
}

func (s *SQLStore) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	return s.repository().GetAPIKey(ctx, id)
}

func (s *SQLStore) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	return s.repository().GetAPIKeyByTokenHash(ctx, tokenHash)
}

func (s *SQLStore) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	return s.repository().ListAPIKeys(ctx)
}

func (s *SQLStore) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	return s.repository().UpdateAPIKeyIfStatus(ctx, key, currentStatus)
}

func (s *SQLStore) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	return s.repository().CreateACMEAccount(ctx, account)
}

func (s *SQLStore) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	return s.repository().GetACMEAccount(ctx, id)
}

func (s *SQLStore) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	return s.repository().ListACMEAccounts(ctx)
}

func (s *SQLStore) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	return s.repository().UpdateACMEAccountIfStatus(ctx, account, currentStatus)
}

func (s *SQLStore) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	return s.repository().CreateACMEOrder(ctx, order)
}

func (s *SQLStore) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	return s.repository().GetACMEOrder(ctx, id)
}

func (s *SQLStore) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	return s.repository().ListACMEOrdersByAccount(ctx, accountID)
}

func (s *SQLStore) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	return s.repository().UpdateACMEOrderIfStatus(ctx, order, currentStatus)
}

func (s *SQLStore) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	return s.repository().CreateACMEAuthorization(ctx, authorization)
}

func (s *SQLStore) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	return s.repository().GetACMEAuthorization(ctx, id)
}

func (s *SQLStore) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	return s.repository().ListACMEAuthorizationsByOrder(ctx, orderID)
}

func (s *SQLStore) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	return s.repository().UpdateACMEAuthorizationIfStatus(ctx, authorization, currentStatus)
}

func (s *SQLStore) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	return s.repository().CreateACMEChallenge(ctx, challenge)
}

func (s *SQLStore) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	return s.repository().GetACMEChallenge(ctx, id)
}

func (s *SQLStore) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	return s.repository().ListACMEChallengesByAuthorization(ctx, authorizationID)
}

func (s *SQLStore) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	return s.repository().UpdateACMEChallengeIfStatus(ctx, challenge, currentStatus)
}

func (s *SQLStore) repository() sqlRepository {
	return sqlRepository{exec: s.db}
}

func (r sqlRepository) WithinTx(ctx context.Context, fn func(Repository) error) error {
	return fn(r)
}

func addSQLStringCondition(args *[]any, conditions *[]string, column string, value string) {
	if value == "" {
		return
	}
	*args = append(*args, value)
	*conditions = append(*conditions, fmt.Sprintf("%s = $%d", column, len(*args)))
}

func appendSQLWhere(query *strings.Builder, conditions []string) {
	if len(conditions) == 0 {
		return
	}
	query.WriteString("\nWHERE ")
	query.WriteString(strings.Join(conditions, " AND "))
}

func appendSQLSort(query *strings.Builder, sortOrder string, createdAtColumn string, idColumn string) {
	if sortOrder == "desc" {
		query.WriteString(fmt.Sprintf("\nORDER BY %s DESC, %s DESC", createdAtColumn, idColumn))
		return
	}
	query.WriteString(fmt.Sprintf("\nORDER BY %s ASC, %s ASC", createdAtColumn, idColumn))
}

func appendSQLLimitOffset(query *strings.Builder, args *[]any, limit int, offset int) {
	if limit <= 0 {
		return
	}
	*args = append(*args, limit)
	query.WriteString(fmt.Sprintf("\nLIMIT $%d", len(*args)))
	if offset > 0 {
		*args = append(*args, offset)
		query.WriteString(fmt.Sprintf(" OFFSET $%d", len(*args)))
	}
}

func sqlJSONStringElementPattern(value string) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return "%" + string(encoded) + "%", nil
}

func (r sqlRepository) CreateIdentity(ctx context.Context, identity domain.Identity) error {
	allowedDNSNames, err := marshalStringSlice(identity.AllowedDNSNames)
	if err != nil {
		return err
	}
	allowedIPAddresses, err := marshalStringSlice(identity.AllowedIPAddresses)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO identities (
	id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		identity.ID,
		string(identity.Type),
		identity.Name,
		identity.ExternalID,
		identity.Owner,
		identity.Team,
		identity.Service,
		identity.Environment,
		identity.DeploymentTarget,
		formatNullableSQLTime(identity.LastSeenAt),
		identity.MetadataJSON,
		allowedDNSNames,
		allowedIPAddresses,
		string(identity.Status),
		formatSQLTime(identity.CreatedAt),
		formatSQLTime(identity.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIdentity(ctx context.Context, id string) (domain.Identity, error) {
	identity, err := scanIdentity(r.exec.QueryRowContext(ctx, `
SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
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
SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
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

func (r sqlRepository) ListIdentitiesQuery(ctx context.Context, query IdentityQuery) ([]domain.Identity, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, type, name, external_id, owner, team, service, environment, deployment_target, last_seen_at,
	metadata_json, allowed_dns_names, allowed_ip_addresses, status, created_at, updated_at
FROM identities`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "owner", query.Owner)
	addSQLStringCondition(&args, &conditions, "team", query.Team)
	addSQLStringCondition(&args, &conditions, "service", query.Service)
	addSQLStringCondition(&args, &conditions, "environment", query.Environment)
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
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
	distributionPoints, err := marshalStringSlice(issuer.CRLDistributionPoints)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO issuers (
	id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)`,
		issuer.ID,
		issuer.Name,
		string(issuer.Kind),
		string(issuer.Status),
		issuer.ParentIssuerID,
		issuer.CertificatePEM,
		issuer.KeyRef,
		issuer.AIAURL,
		distributionPoints,
		issuer.TrustAnchor,
		formatSQLTime(issuer.CreatedAt),
		formatSQLTime(issuer.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetIssuer(ctx context.Context, id string) (domain.Issuer, error) {
	issuer, err := scanIssuer(r.exec.QueryRowContext(ctx, `
SELECT id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
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
SELECT id, name, kind, status, parent_issuer_id, certificate_pem, key_ref, aia_url, crl_distribution_points, trust_anchor, created_at, updated_at
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
	id, name, type, status, url, secret, event_types, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9
)`,
		endpoint.ID,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		endpoint.Secret,
		eventTypes,
		formatSQLTime(endpoint.CreatedAt),
		formatSQLTime(endpoint.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetNotificationEndpoint(ctx context.Context, id string) (domain.NotificationEndpoint, error) {
	endpoint, err := scanNotificationEndpoint(r.exec.QueryRowContext(ctx, `
SELECT id, name, type, status, url, secret, event_types, created_at, updated_at
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
SELECT id, name, type, status, url, secret, event_types, created_at, updated_at
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
	secret = $5,
	event_types = $6,
	created_at = $7,
	updated_at = $8
WHERE id = $9 AND status = $10`,
		endpoint.Name,
		string(endpoint.Type),
		string(endpoint.Status),
		endpoint.URL,
		endpoint.Secret,
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
	allowedKeyAlgorithms, err := marshalStringSlice(profile.AllowedKeyAlgorithms)
	if err != nil {
		return err
	}
	allowedSignatureAlgorithms, err := marshalStringSlice(profile.AllowedSignatureAlgorithms)
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
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
)`,
		profile.ID,
		profile.Name,
		profile.Description,
		profile.IssuerID,
		profile.ValidityPeriodSeconds,
		profile.SubjectTemplate,
		allowedDNSPatterns,
		allowedIPRanges,
		allowedKeyAlgorithms,
		profile.MinKeySizeBits,
		allowedSignatureAlgorithms,
		keyUsage,
		extendedKeyUsage,
		basicConstraints,
		profile.SubjectKeyIdentifier,
		profile.AuthorityKeyIdentifier,
		profile.PublicTLS,
		formatSQLTime(profile.CreatedAt),
		formatSQLTime(profile.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error) {
	profile, err := scanCertificateProfile(r.exec.QueryRowContext(ctx, `
SELECT id, name, description, issuer_id, validity_period_seconds, subject_template,
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
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
	allowed_dns_patterns, allowed_ip_ranges, allowed_key_algorithms, min_key_size_bits,
	allowed_signature_algorithms, key_usage, extended_key_usage, basic_constraints,
	subject_key_identifier, authority_key_identifier, public_tls, created_at, updated_at
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

func (r sqlRepository) ListEnrollmentsQuery(ctx context.Context, query EnrollmentQuery) ([]domain.Enrollment, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, identity_id, issuer_id, certificate_profile_id, csr_pem, status, requested_subject,
	requested_dns_names, requested_ip_addresses, csr_dns_names, csr_ip_addresses, requested_not_after,
	approved_by, approved_at, created_at, updated_at
FROM enrollments`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "identity_id", query.IdentityID)
	addSQLStringCondition(&args, &conditions, "issuer_id", query.IssuerID)
	addSQLStringCondition(&args, &conditions, "certificate_profile_id", query.ProfileID)
	if query.Status != "" {
		addSQLStringCondition(&args, &conditions, "status", string(query.Status))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
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
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
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

func (r sqlRepository) GetCertificateByEnrollmentID(ctx context.Context, enrollmentID string) (domain.Certificate, error) {
	certificate, err := scanCertificate(r.exec.QueryRowContext(ctx, `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE enrollment_id = $1`, enrollmentID))
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

func (r sqlRepository) ListCertificatesQuery(ctx context.Context, query CertificateQuery) ([]domain.Certificate, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT c.id, c.identity_id, c.issuer_id, c.enrollment_id, c.certificate_profile_id, c.serial_number, c.subject,
	c.dns_names, c.ip_addresses, c.not_before, c.not_after, c.status, c.certificate_pem,
	c.renewal_notified_at, c.created_at, c.updated_at
FROM certificates c`)
	if query.Owner != "" || query.Team != "" || query.Service != "" || query.Environment != "" {
		sqlQuery.WriteString(`
JOIN identities i ON i.id = c.identity_id`)
	}
	args := make([]any, 0)
	conditions := make([]string, 0)
	addSQLStringCondition(&args, &conditions, "i.owner", query.Owner)
	addSQLStringCondition(&args, &conditions, "i.team", query.Team)
	addSQLStringCondition(&args, &conditions, "i.service", query.Service)
	addSQLStringCondition(&args, &conditions, "i.environment", query.Environment)
	addSQLStringCondition(&args, &conditions, "c.issuer_id", query.IssuerID)
	addSQLStringCondition(&args, &conditions, "c.certificate_profile_id", query.ProfileID)
	addSQLStringCondition(&args, &conditions, "c.status", query.RevocationState)
	if query.SAN != "" {
		pattern, err := sqlJSONStringElementPattern(query.SAN)
		if err != nil {
			return nil, err
		}
		args = append(args, pattern, pattern)
		conditions = append(conditions, fmt.Sprintf("(c.dns_names LIKE $%d OR c.ip_addresses LIKE $%d)", len(args)-1, len(args)))
	}
	if query.RenewalState == "notified" {
		conditions = append(conditions, "c.renewal_notified_at IS NOT NULL")
	} else if query.RenewalState == "unnotified" {
		conditions = append(conditions, "c.renewal_notified_at IS NULL")
	}
	if !query.ExpiresAfter.IsZero() {
		args = append(args, formatSQLTime(query.ExpiresAfter))
		conditions = append(conditions, fmt.Sprintf("c.not_after > $%d", len(args)))
	}
	if !query.ExpiresBefore.IsZero() {
		args = append(args, formatSQLTime(query.ExpiresBefore))
		conditions = append(conditions, fmt.Sprintf("c.not_after <= $%d", len(args)))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "c.created_at", "c.id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
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

func (r sqlRepository) ListCertificateInventory(ctx context.Context, filter CertificateInventoryFilter) ([]CertificateInventoryRecord, error) {
	query := `
SELECT
	c.id, c.identity_id, c.issuer_id, c.enrollment_id, c.certificate_profile_id, c.serial_number, c.subject,
	c.dns_names, c.ip_addresses, c.not_before, c.not_after, c.status, c.certificate_pem,
	c.renewal_notified_at, c.created_at, c.updated_at,
	i.id, i.type, i.name, i.external_id, i.owner, i.team, i.service, i.environment, i.deployment_target, i.last_seen_at,
	i.metadata_json, i.allowed_dns_names, i.allowed_ip_addresses, i.status, i.created_at, i.updated_at,
	iss.id, iss.name, iss.kind, iss.status, iss.parent_issuer_id, iss.certificate_pem, iss.key_ref, iss.aia_url, iss.crl_distribution_points, iss.trust_anchor, iss.created_at, iss.updated_at
FROM certificates c
JOIN identities i ON i.id = c.identity_id
JOIN issuers iss ON iss.id = c.issuer_id`
	args := make([]any, 0)
	conditions := make([]string, 0)
	addCondition := func(condition string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(condition, len(args)))
	}
	if filter.Owner != "" {
		addCondition("i.owner = $%d", filter.Owner)
	}
	if filter.Team != "" {
		addCondition("i.team = $%d", filter.Team)
	}
	if filter.Service != "" {
		addCondition("i.service = $%d", filter.Service)
	}
	if filter.Environment != "" {
		addCondition("i.environment = $%d", filter.Environment)
	}
	if filter.IssuerID != "" {
		addCondition("c.issuer_id = $%d", filter.IssuerID)
	}
	if filter.ProfileID != "" {
		addCondition("c.certificate_profile_id = $%d", filter.ProfileID)
	}
	if filter.RevocationState != "" {
		addCondition("c.status = $%d", filter.RevocationState)
	}
	if len(conditions) > 0 {
		query += "\nWHERE " + strings.Join(conditions, " AND ")
	}
	query += "\nORDER BY c.id"
	if filter.Limit > 0 {
		args = append(args, filter.Limit, filter.Offset)
		query += fmt.Sprintf("\nLIMIT $%d OFFSET $%d", len(args)-1, len(args))
	} else if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf("\nLIMIT 9223372036854775807 OFFSET $%d", len(args))
	}

	rows, err := r.exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]CertificateInventoryRecord, 0)
	for rows.Next() {
		record, err := scanCertificateInventoryRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func (r sqlRepository) ListCertificatesExpiringWithin(ctx context.Context, now time.Time, cutoff time.Time, limit int, offset int) ([]domain.Certificate, error) {
	query := `
SELECT id, identity_id, issuer_id, enrollment_id, certificate_profile_id, serial_number, subject,
	dns_names, ip_addresses, not_before, not_after, status, certificate_pem,
	renewal_notified_at, created_at, updated_at
FROM certificates
WHERE status = $1 AND not_after > $2 AND not_after <= $3
ORDER BY not_after, id`
	args := []any{string(domain.CertificateValid), formatSQLTime(now), formatSQLTime(cutoff)}
	if limit > 0 {
		query += ` LIMIT $4 OFFSET $5`
		args = append(args, limit, offset)
	}
	rows, err := r.exec.QueryContext(ctx, query, args...)
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

func (r sqlRepository) CreateIssuanceAttempt(ctx context.Context, attempt domain.IssuanceAttempt) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO certificate_issuance_attempts (
	enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number, subject,
	not_before, not_after, signing_started_at, signed_at, finalized_at, last_error, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
)`,
		attempt.EnrollmentID,
		string(attempt.Status),
		formatNullableSQLTime(attempt.LeaseExpiresAt),
		attempt.CertificateID,
		attempt.CertificatePEM,
		attempt.SerialNumber,
		attempt.Subject,
		formatNullableSQLTime(attempt.NotBefore),
		formatNullableSQLTime(attempt.NotAfter),
		formatNullableSQLTime(attempt.SigningStartedAt),
		formatNullableSQLTime(attempt.SignedAt),
		formatNullableSQLTime(attempt.FinalizedAt),
		attempt.LastError,
		formatSQLTime(attempt.CreatedAt),
		formatSQLTime(attempt.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetIssuanceAttempt(ctx context.Context, enrollmentID string) (domain.IssuanceAttempt, error) {
	attempt, err := scanIssuanceAttempt(r.exec.QueryRowContext(ctx, `
SELECT enrollment_id, status, lease_expires_at, certificate_id, certificate_pem, serial_number, subject,
	not_before, not_after, signing_started_at, signed_at, finalized_at, last_error, created_at, updated_at
FROM certificate_issuance_attempts
WHERE enrollment_id = $1`, enrollmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.IssuanceAttempt{}, domain.ErrIssuanceAttemptNotFound
	}
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	return attempt, nil
}

func (r sqlRepository) UpdateIssuanceAttemptIfCurrent(ctx context.Context, attempt domain.IssuanceAttempt, current domain.IssuanceAttempt) error {
	currentLeaseExpiresAt := formatNullableSQLTime(current.LeaseExpiresAt)
	result, err := r.exec.ExecContext(ctx, `
UPDATE certificate_issuance_attempts
SET status = $1,
	lease_expires_at = $2,
	certificate_id = $3,
	certificate_pem = $4,
	serial_number = $5,
	subject = $6,
	not_before = $7,
	not_after = $8,
	signing_started_at = $9,
	signed_at = $10,
	finalized_at = $11,
	last_error = $12,
	created_at = $13,
	updated_at = $14
WHERE enrollment_id = $15
	AND status = $16
	AND updated_at = $17
	AND lease_expires_at IS NOT DISTINCT FROM $18`,
		string(attempt.Status),
		formatNullableSQLTime(attempt.LeaseExpiresAt),
		attempt.CertificateID,
		attempt.CertificatePEM,
		attempt.SerialNumber,
		attempt.Subject,
		formatNullableSQLTime(attempt.NotBefore),
		formatNullableSQLTime(attempt.NotAfter),
		formatNullableSQLTime(attempt.SigningStartedAt),
		formatNullableSQLTime(attempt.SignedAt),
		formatNullableSQLTime(attempt.FinalizedAt),
		attempt.LastError,
		formatSQLTime(attempt.CreatedAt),
		formatSQLTime(attempt.UpdatedAt),
		attempt.EnrollmentID,
		string(current.Status),
		formatSQLTime(current.UpdatedAt),
		currentLeaseExpiresAt,
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
	if _, err := r.GetIssuanceAttempt(ctx, attempt.EnrollmentID); errors.Is(err, domain.ErrIssuanceAttemptNotFound) {
		return err
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
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
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
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

func (r sqlRepository) ListAuditEventsQuery(ctx context.Context, query AuditEventQuery) ([]domain.AuditEvent, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, actor, action, resource_type, resource_id, metadata_json, created_at
FROM audit_events`)
	where := make([]string, 0)
	args := make([]any, 0)
	addStringFilter := func(column string, value string) {
		if value == "" {
			return
		}
		args = append(args, value)
		where = append(where, fmt.Sprintf("%s = $%d", column, len(args)))
	}
	addStringFilter("actor", query.Actor)
	addStringFilter("action", query.Action)
	addStringFilter("resource_type", query.ResourceType)
	addStringFilter("resource_id", query.ResourceID)
	if !query.CreatedFrom.IsZero() {
		args = append(args, formatSQLTime(query.CreatedFrom))
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.CreatedTo.IsZero() {
		args = append(args, formatSQLTime(query.CreatedTo))
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	if len(where) > 0 {
		sqlQuery.WriteString("\nWHERE ")
		sqlQuery.WriteString(strings.Join(where, " AND "))
	}
	if query.Sort == "desc" {
		sqlQuery.WriteString("\nORDER BY created_at DESC, id DESC")
	} else {
		sqlQuery.WriteString("\nORDER BY created_at ASC, id ASC")
	}
	if query.Limit > 0 {
		args = append(args, query.Limit)
		sqlQuery.WriteString(fmt.Sprintf("\nLIMIT $%d", len(args)))
		if query.Offset > 0 {
			args = append(args, query.Offset)
			sqlQuery.WriteString(fmt.Sprintf(" OFFSET $%d", len(args)))
		}
	}

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
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

func (r sqlRepository) DeleteAuditEventsBefore(ctx context.Context, before time.Time) (int, error) {
	result, err := r.exec.ExecContext(ctx, `
DELETE FROM audit_events
WHERE created_at < $1`, formatSQLTime(before))
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(rows), nil
}

func (r sqlRepository) CreateOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO outbox_messages (
	id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
)`,
		message.ID,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
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
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
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
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
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

func (r sqlRepository) ListOutboxMessagesQuery(ctx context.Context, query OutboxMessageQuery) ([]domain.OutboxMessage, error) {
	sqlQuery := strings.Builder{}
	sqlQuery.WriteString(`SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages`)
	args := make([]any, 0)
	conditions := make([]string, 0)
	if query.Status != "" {
		addSQLStringCondition(&args, &conditions, "status", string(query.Status))
	}
	addSQLStringCondition(&args, &conditions, "type", query.Type)
	if !query.CreatedFrom.IsZero() {
		args = append(args, formatSQLTime(query.CreatedFrom))
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if !query.CreatedTo.IsZero() {
		args = append(args, formatSQLTime(query.CreatedTo))
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	appendSQLWhere(&sqlQuery, conditions)
	appendSQLSort(&sqlQuery, query.Sort, "created_at", "id")
	appendSQLLimitOffset(&sqlQuery, &args, query.Limit, query.Offset)

	rows, err := r.exec.QueryContext(ctx, sqlQuery.String(), args...)
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
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE (status = $1 AND available_at <= $3)
	OR (status = $2 AND processing_deadline_at IS NOT NULL AND processing_deadline_at <= $3)
ORDER BY CASE WHEN status = $1 THEN available_at ELSE processing_deadline_at END, created_at, id
LIMIT $4`, string(domain.OutboxPending), string(domain.OutboxProcessing), formatSQLTime(now), limit)
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
	processing_deadline_at = $5,
	attempt_count = $6,
	max_attempts = $7,
	last_error = $8,
	created_at = $9,
	updated_at = $10
WHERE id = $11 AND status = $12`,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
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
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
FROM outbox_messages
WHERE id = $1`, message.ID)); errors.Is(err, sql.ErrNoRows) {
		return domain.ErrOutboxMessageNotFound
	} else if err != nil {
		return err
	}
	return domain.ErrInvalidTransition
}

func (r sqlRepository) UpdateOutboxMessageIfCurrent(ctx context.Context, message domain.OutboxMessage, current domain.OutboxMessage) error {
	currentProcessingDeadlineAt := formatNullableSQLTime(current.ProcessingDeadlineAt)
	result, err := r.exec.ExecContext(ctx, `
UPDATE outbox_messages
SET type = $1,
	payload_json = $2,
	status = $3,
	available_at = $4,
	processing_deadline_at = $5,
	attempt_count = $6,
	max_attempts = $7,
	last_error = $8,
	created_at = $9,
	updated_at = $10
WHERE id = $11
	AND status = $12
	AND updated_at = $13
	AND ((processing_deadline_at IS NULL AND $14 IS NULL) OR processing_deadline_at = $14)`,
		message.Type,
		message.PayloadJSON,
		string(message.Status),
		formatSQLTime(message.AvailableAt),
		formatNullableSQLTime(message.ProcessingDeadlineAt),
		message.AttemptCount,
		message.MaxAttempts,
		message.LastError,
		formatSQLTime(message.CreatedAt),
		formatSQLTime(message.UpdatedAt),
		message.ID,
		string(current.Status),
		formatSQLTime(current.UpdatedAt),
		currentProcessingDeadlineAt,
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
SELECT id, type, payload_json, status, available_at, processing_deadline_at, attempt_count, max_attempts, last_error, created_at, updated_at
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

func (r sqlRepository) GetWebhookDelivery(ctx context.Context, outboxMessageID string, endpointID string) (domain.WebhookDelivery, error) {
	delivery, err := scanWebhookDelivery(r.exec.QueryRowContext(ctx, `
SELECT outbox_message_id, endpoint_id, status, attempt_count, last_error, last_attempted_at, created_at, updated_at
FROM webhook_deliveries
WHERE outbox_message_id = $1 AND endpoint_id = $2`, outboxMessageID, endpointID))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.WebhookDelivery{}, domain.ErrWebhookDeliveryNotFound
	}
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	return delivery, nil
}

func (r sqlRepository) UpsertWebhookDelivery(ctx context.Context, delivery domain.WebhookDelivery) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO webhook_deliveries (
	outbox_message_id, endpoint_id, status, attempt_count, last_error, last_attempted_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)
ON CONFLICT (outbox_message_id, endpoint_id) DO UPDATE SET
	status = excluded.status,
	attempt_count = excluded.attempt_count,
	last_error = excluded.last_error,
	last_attempted_at = excluded.last_attempted_at,
	updated_at = excluded.updated_at`,
		delivery.OutboxMessageID,
		delivery.EndpointID,
		string(delivery.Status),
		delivery.AttemptCount,
		delivery.LastError,
		formatSQLTime(delivery.LastAttemptedAt),
		formatSQLTime(delivery.CreatedAt),
		formatSQLTime(delivery.UpdatedAt),
	)
	return err
}

func (r sqlRepository) CreateAPIKey(ctx context.Context, key domain.APIKey) error {
	scopes, err := marshalAPIKeyScopes(key.Scopes)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO api_keys (
	id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)`,
		key.ID,
		key.Name,
		key.TokenHash,
		string(key.Status),
		key.Actor,
		scopes,
		formatNullableSQLTime(key.ExpiresAt),
		formatNullableSQLTime(key.LastUsedAt),
		formatSQLTime(key.CreatedAt),
		formatSQLTime(key.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetAPIKey(ctx context.Context, id string) (domain.APIKey, error) {
	key, err := scanAPIKey(r.exec.QueryRowContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (r sqlRepository) GetAPIKeyByTokenHash(ctx context.Context, tokenHash string) (domain.APIKey, error) {
	key, err := scanAPIKey(r.exec.QueryRowContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
WHERE token_hash = $1`, tokenHash))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.APIKey{}, domain.ErrAPIKeyNotFound
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (r sqlRepository) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, name, token_hash, status, actor, scopes, expires_at, last_used_at, created_at, updated_at
FROM api_keys
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := make([]domain.APIKey, 0)
	for rows.Next() {
		key, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

func (r sqlRepository) UpdateAPIKeyIfStatus(ctx context.Context, key domain.APIKey, currentStatus domain.APIKeyStatus) error {
	scopes, err := marshalAPIKeyScopes(key.Scopes)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE api_keys
SET name = $1, token_hash = $2, status = $3, actor = $4, scopes = $5, expires_at = $6, last_used_at = $7, updated_at = $8
WHERE id = $9 AND status = $10`,
		key.Name,
		key.TokenHash,
		string(key.Status),
		key.Actor,
		scopes,
		formatNullableSQLTime(key.ExpiresAt),
		formatNullableSQLTime(key.LastUsedAt),
		formatSQLTime(key.UpdatedAt),
		key.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		if _, err := r.GetAPIKey(ctx, key.ID); errors.Is(err, domain.ErrAPIKeyNotFound) {
			return domain.ErrAPIKeyNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEAccount(ctx context.Context, account domain.ACMEAccount) error {
	contacts, err := marshalStringSlice(account.Contacts)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO acme_accounts (
	id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		account.ID,
		contacts,
		string(account.Status),
		account.TermsOfServiceAgreed,
		account.KeyThumbprint,
		account.KeyJWKJSON,
		formatSQLTime(account.CreatedAt),
		formatSQLTime(account.UpdatedAt),
	)
	if isUniqueConstraintError(err) {
		return domain.ErrInvalidTransition
	}
	return err
}

func (r sqlRepository) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	account, err := scanACMEAccount(r.exec.QueryRowContext(ctx, `
SELECT id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
FROM acme_accounts
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEAccount{}, domain.ErrACMEAccountNotFound
	}
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	return account, nil
}

func (r sqlRepository) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, contacts, status, terms_of_service_agreed, key_thumbprint, key_jwk_json, created_at, updated_at
FROM acme_accounts
ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]domain.ACMEAccount, 0)
	for rows.Next() {
		account, err := scanACMEAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return accounts, nil
}

func (r sqlRepository) UpdateACMEAccountIfStatus(ctx context.Context, account domain.ACMEAccount, currentStatus domain.ACMEAccountStatus) error {
	contacts, err := marshalStringSlice(account.Contacts)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_accounts
SET contacts = $1, status = $2, terms_of_service_agreed = $3, key_thumbprint = $4, key_jwk_json = $5, updated_at = $6
WHERE id = $7 AND status = $8`,
		contacts,
		string(account.Status),
		account.TermsOfServiceAgreed,
		account.KeyThumbprint,
		account.KeyJWKJSON,
		formatSQLTime(account.UpdatedAt),
		account.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		if _, err := r.GetACMEAccount(ctx, account.ID); errors.Is(err, domain.ErrACMEAccountNotFound) {
			return domain.ErrACMEAccountNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEOrder(ctx context.Context, order domain.ACMEOrder) error {
	dnsNames, err := marshalStringSlice(order.RequestedDNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(order.RequestedIPAddresses)
	if err != nil {
		return err
	}
	_, err = r.exec.ExecContext(ctx, `
INSERT INTO acme_orders (
	id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
)`,
		order.ID,
		order.AccountID,
		order.IdentityID,
		order.IssuerID,
		order.CertificateProfileID,
		string(order.Status),
		order.CSRPEM,
		order.RequestedSubject,
		dnsNames,
		ipAddresses,
		formatSQLTime(order.RequestedNotAfter),
		order.EnrollmentID,
		order.CertificateID,
		formatSQLTime(order.ExpiresAt),
		formatSQLTime(order.CreatedAt),
		formatSQLTime(order.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	order, err := scanACMEOrder(r.exec.QueryRowContext(ctx, `
SELECT id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
FROM acme_orders
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEOrder{}, domain.ErrACMEOrderNotFound
	}
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	return order, nil
}

func (r sqlRepository) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, account_id, identity_id, issuer_id, certificate_profile_id, status, csr_pem,
	requested_subject, requested_dns_names, requested_ip_addresses, requested_not_after,
	enrollment_id, certificate_id, expires_at, created_at, updated_at
FROM acme_orders
WHERE account_id = $1
ORDER BY created_at, id`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	orders := make([]domain.ACMEOrder, 0)
	for rows.Next() {
		order, err := scanACMEOrder(rows)
		if err != nil {
			return nil, err
		}
		orders = append(orders, order)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return orders, nil
}

func (r sqlRepository) UpdateACMEOrderIfStatus(ctx context.Context, order domain.ACMEOrder, currentStatus domain.ACMEOrderStatus) error {
	dnsNames, err := marshalStringSlice(order.RequestedDNSNames)
	if err != nil {
		return err
	}
	ipAddresses, err := marshalStringSlice(order.RequestedIPAddresses)
	if err != nil {
		return err
	}
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_orders
SET account_id = $1, identity_id = $2, issuer_id = $3, certificate_profile_id = $4,
	status = $5, csr_pem = $6, requested_subject = $7, requested_dns_names = $8,
	requested_ip_addresses = $9, requested_not_after = $10, enrollment_id = $11,
	certificate_id = $12, expires_at = $13, created_at = $14, updated_at = $15
WHERE id = $16 AND status = $17`,
		order.AccountID,
		order.IdentityID,
		order.IssuerID,
		order.CertificateProfileID,
		string(order.Status),
		order.CSRPEM,
		order.RequestedSubject,
		dnsNames,
		ipAddresses,
		formatSQLTime(order.RequestedNotAfter),
		order.EnrollmentID,
		order.CertificateID,
		formatSQLTime(order.ExpiresAt),
		formatSQLTime(order.CreatedAt),
		formatSQLTime(order.UpdatedAt),
		order.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		if _, err := r.GetACMEOrder(ctx, order.ID); errors.Is(err, domain.ErrACMEOrderNotFound) {
			return domain.ErrACMEOrderNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEAuthorization(ctx context.Context, authorization domain.ACMEAuthorization) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO acme_authorizations (
	id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8, $9
)`,
		authorization.ID,
		authorization.OrderID,
		authorization.IdentifierType,
		authorization.IdentifierValue,
		string(authorization.Status),
		formatSQLTime(authorization.ExpiresAt),
		formatNullableSQLTime(authorization.ValidationReuseExpiresAt),
		formatSQLTime(authorization.CreatedAt),
		formatSQLTime(authorization.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	authorization, err := scanACMEAuthorization(r.exec.QueryRowContext(ctx, `
SELECT id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
FROM acme_authorizations
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEAuthorization{}, domain.ErrACMEAuthorizationNotFound
	}
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	return authorization, nil
}

func (r sqlRepository) ListACMEAuthorizationsByOrder(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, order_id, identifier_type, identifier_value, status, expires_at, validation_reuse_expires_at, created_at, updated_at
FROM acme_authorizations
WHERE order_id = $1
ORDER BY created_at, id`, orderID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	authorizations := make([]domain.ACMEAuthorization, 0)
	for rows.Next() {
		authorization, err := scanACMEAuthorization(rows)
		if err != nil {
			return nil, err
		}
		authorizations = append(authorizations, authorization)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return authorizations, nil
}

func (r sqlRepository) UpdateACMEAuthorizationIfStatus(ctx context.Context, authorization domain.ACMEAuthorization, currentStatus domain.ACMEAuthorizationStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_authorizations
SET order_id = $1, identifier_type = $2, identifier_value = $3, status = $4, expires_at = $5, validation_reuse_expires_at = $6, created_at = $7, updated_at = $8
WHERE id = $9 AND status = $10`,
		authorization.OrderID,
		authorization.IdentifierType,
		authorization.IdentifierValue,
		string(authorization.Status),
		formatSQLTime(authorization.ExpiresAt),
		formatNullableSQLTime(authorization.ValidationReuseExpiresAt),
		formatSQLTime(authorization.CreatedAt),
		formatSQLTime(authorization.UpdatedAt),
		authorization.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return domain.ErrInvalidTransition
	}
	return nil
}

func (r sqlRepository) CreateACMEChallenge(ctx context.Context, challenge domain.ACMEChallenge) error {
	_, err := r.exec.ExecContext(ctx, `
INSERT INTO acme_challenges (
	id, authorization_id, type, token, status, validated_at, created_at, updated_at
) VALUES (
	$1, $2, $3, $4, $5, $6, $7, $8
)`,
		challenge.ID,
		challenge.AuthorizationID,
		string(challenge.Type),
		challenge.Token,
		string(challenge.Status),
		formatNullableSQLTime(challenge.ValidatedAt),
		formatSQLTime(challenge.CreatedAt),
		formatSQLTime(challenge.UpdatedAt),
	)
	return err
}

func (r sqlRepository) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	challenge, err := scanACMEChallenge(r.exec.QueryRowContext(ctx, `
SELECT id, authorization_id, type, token, status, validated_at, created_at, updated_at
FROM acme_challenges
WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ACMEChallenge{}, domain.ErrACMEChallengeNotFound
	}
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	return challenge, nil
}

func (r sqlRepository) ListACMEChallengesByAuthorization(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	rows, err := r.exec.QueryContext(ctx, `
SELECT id, authorization_id, type, token, status, validated_at, created_at, updated_at
FROM acme_challenges
WHERE authorization_id = $1
ORDER BY created_at, id`, authorizationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	challenges := make([]domain.ACMEChallenge, 0)
	for rows.Next() {
		challenge, err := scanACMEChallenge(rows)
		if err != nil {
			return nil, err
		}
		challenges = append(challenges, challenge)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return challenges, nil
}

func (r sqlRepository) UpdateACMEChallengeIfStatus(ctx context.Context, challenge domain.ACMEChallenge, currentStatus domain.ACMEChallengeStatus) error {
	result, err := r.exec.ExecContext(ctx, `
UPDATE acme_challenges
SET authorization_id = $1, type = $2, token = $3, status = $4, validated_at = $5, created_at = $6, updated_at = $7
WHERE id = $8 AND status = $9`,
		challenge.AuthorizationID,
		string(challenge.Type),
		challenge.Token,
		string(challenge.Status),
		formatNullableSQLTime(challenge.ValidatedAt),
		formatSQLTime(challenge.CreatedAt),
		formatSQLTime(challenge.UpdatedAt),
		challenge.ID,
		string(currentStatus),
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		if _, err := r.GetACMEChallenge(ctx, challenge.ID); errors.Is(err, domain.ErrACMEChallengeNotFound) {
			return domain.ErrACMEChallengeNotFound
		}
		return domain.ErrInvalidTransition
	}
	return nil
}

func scanACMEAccount(scanner sqlScanner) (domain.ACMEAccount, error) {
	var account domain.ACMEAccount
	var status string
	var contacts string
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&account.ID,
		&contacts,
		&status,
		&account.TermsOfServiceAgreed,
		&account.KeyThumbprint,
		&account.KeyJWKJSON,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedContacts, err := unmarshalStringSlice(contacts)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEAccount{}, err
	}
	account.Contacts = parsedContacts
	account.Status = domain.ACMEAccountStatus(status)
	account.CreatedAt = parsedCreatedAt
	account.UpdatedAt = parsedUpdatedAt
	return account, nil
}

func scanACMEOrder(scanner sqlScanner) (domain.ACMEOrder, error) {
	var order domain.ACMEOrder
	var status string
	var requestedDNSNames string
	var requestedIPAddresses string
	var requestedNotAfter any
	var expiresAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&order.ID,
		&order.AccountID,
		&order.IdentityID,
		&order.IssuerID,
		&order.CertificateProfileID,
		&status,
		&order.CSRPEM,
		&order.RequestedSubject,
		&requestedDNSNames,
		&requestedIPAddresses,
		&requestedNotAfter,
		&order.EnrollmentID,
		&order.CertificateID,
		&expiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEOrder{}, err
	}
	dnsNames, err := unmarshalStringSlice(requestedDNSNames)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	ipAddresses, err := unmarshalStringSlice(requestedIPAddresses)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedRequestedNotAfter, err := parseSQLTime(requestedNotAfter)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	order.Status = domain.ACMEOrderStatus(status)
	order.RequestedDNSNames = dnsNames
	order.RequestedIPAddresses = ipAddresses
	order.RequestedNotAfter = parsedRequestedNotAfter
	order.ExpiresAt = parsedExpiresAt
	order.CreatedAt = parsedCreatedAt
	order.UpdatedAt = parsedUpdatedAt
	return order, nil
}

func scanACMEAuthorization(scanner sqlScanner) (domain.ACMEAuthorization, error) {
	var authorization domain.ACMEAuthorization
	var status string
	var expiresAt any
	var validationReuseExpiresAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&authorization.ID,
		&authorization.OrderID,
		&authorization.IdentifierType,
		&authorization.IdentifierValue,
		&status,
		&expiresAt,
		&validationReuseExpiresAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedValidationReuseExpiresAt, err := parseSQLTime(validationReuseExpiresAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	authorization.Status = domain.ACMEAuthorizationStatus(status)
	authorization.ExpiresAt = parsedExpiresAt
	authorization.ValidationReuseExpiresAt = parsedValidationReuseExpiresAt
	authorization.CreatedAt = parsedCreatedAt
	authorization.UpdatedAt = parsedUpdatedAt
	return authorization, nil
}

func scanACMEChallenge(scanner sqlScanner) (domain.ACMEChallenge, error) {
	var challenge domain.ACMEChallenge
	var challengeType string
	var status string
	var validatedAt any
	var createdAt any
	var updatedAt any
	if err := scanner.Scan(
		&challenge.ID,
		&challenge.AuthorizationID,
		&challengeType,
		&challenge.Token,
		&status,
		&validatedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedValidatedAt, err := parseSQLTime(validatedAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	challenge.Type = domain.ACMEChallengeType(challengeType)
	challenge.Status = domain.ACMEChallengeStatus(status)
	challenge.ValidatedAt = parsedValidatedAt
	challenge.CreatedAt = parsedCreatedAt
	challenge.UpdatedAt = parsedUpdatedAt
	return challenge, nil
}

func scanIdentity(scanner sqlScanner) (domain.Identity, error) {
	var identity domain.Identity
	var identityType string
	var status string
	var allowedDNSNames string
	var allowedIPAddresses string
	var lastSeenAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&identity.ID,
		&identityType,
		&identity.Name,
		&identity.ExternalID,
		&identity.Owner,
		&identity.Team,
		&identity.Service,
		&identity.Environment,
		&identity.DeploymentTarget,
		&lastSeenAt,
		&identity.MetadataJSON,
		&allowedDNSNames,
		&allowedIPAddresses,
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
	parsedLastSeenAt, err := parseSQLTime(lastSeenAt)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedAllowedDNSNames, err := unmarshalStringSlice(allowedDNSNames)
	if err != nil {
		return domain.Identity{}, err
	}
	parsedAllowedIPAddresses, err := unmarshalStringSlice(allowedIPAddresses)
	if err != nil {
		return domain.Identity{}, err
	}

	identity.Type = domain.IdentityType(identityType)
	identity.LastSeenAt = parsedLastSeenAt
	identity.AllowedDNSNames = parsedAllowedDNSNames
	identity.AllowedIPAddresses = parsedAllowedIPAddresses
	identity.Status = domain.IdentityStatus(status)
	identity.CreatedAt = parsedCreatedAt
	identity.UpdatedAt = parsedUpdatedAt
	return identity, nil
}

func scanAPIKey(scanner sqlScanner) (domain.APIKey, error) {
	var key domain.APIKey
	var status string
	var scopes string
	var expiresAt any
	var lastUsedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&key.ID,
		&key.Name,
		&key.TokenHash,
		&status,
		&key.Actor,
		&scopes,
		&expiresAt,
		&lastUsedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.APIKey{}, err
	}

	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedScopes, err := unmarshalAPIKeyScopes(scopes)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedExpiresAt, err := parseSQLTime(expiresAt)
	if err != nil {
		return domain.APIKey{}, err
	}
	parsedLastUsedAt, err := parseSQLTime(lastUsedAt)
	if err != nil {
		return domain.APIKey{}, err
	}

	key.Status = domain.APIKeyStatus(status)
	key.Scopes = parsedScopes
	key.ExpiresAt = parsedExpiresAt
	key.LastUsedAt = parsedLastUsedAt
	key.CreatedAt = parsedCreatedAt
	key.UpdatedAt = parsedUpdatedAt
	return key, nil
}

func scanIssuer(scanner sqlScanner) (domain.Issuer, error) {
	var issuer domain.Issuer
	var kind string
	var status string
	var distributionPoints string
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&issuer.ID,
		&issuer.Name,
		&kind,
		&status,
		&issuer.ParentIssuerID,
		&issuer.CertificatePEM,
		&issuer.KeyRef,
		&issuer.AIAURL,
		&distributionPoints,
		&issuer.TrustAnchor,
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
	parsedDistributionPoints, err := unmarshalStringSlice(distributionPoints)
	if err != nil {
		return domain.Issuer{}, err
	}

	issuer.Kind = domain.IssuerKind(kind)
	issuer.Status = domain.IssuerStatus(status)
	issuer.CRLDistributionPoints = parsedDistributionPoints
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
		&endpoint.Secret,
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
	var allowedKeyAlgorithms string
	var allowedSignatureAlgorithms string
	var keyUsage string
	var extendedKeyUsage string
	var basicConstraints string
	var subjectKeyIdentifier bool
	var authorityKeyIdentifier bool
	var publicTLS bool
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
		&allowedKeyAlgorithms,
		&profile.MinKeySizeBits,
		&allowedSignatureAlgorithms,
		&keyUsage,
		&extendedKeyUsage,
		&basicConstraints,
		&subjectKeyIdentifier,
		&authorityKeyIdentifier,
		&publicTLS,
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
	parsedAllowedKeyAlgorithms, err := unmarshalStringSlice(allowedKeyAlgorithms)
	if err != nil {
		return domain.CertificateProfile{}, err
	}
	parsedAllowedSignatureAlgorithms, err := unmarshalStringSlice(allowedSignatureAlgorithms)
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
	profile.AllowedKeyAlgorithms = parsedAllowedKeyAlgorithms
	profile.AllowedSignatureAlgorithms = parsedAllowedSignatureAlgorithms
	profile.SubjectKeyIdentifier = subjectKeyIdentifier
	profile.AuthorityKeyIdentifier = authorityKeyIdentifier
	profile.PublicTLS = publicTLS
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

func scanCertificateInventoryRecord(scanner sqlScanner) (CertificateInventoryRecord, error) {
	var record CertificateInventoryRecord
	var certificateStatus string
	var dnsNames string
	var ipAddresses string
	var notBefore any
	var notAfter any
	var renewalNotifiedAt any
	var certificateCreatedAt any
	var certificateUpdatedAt any
	var identityType string
	var identityStatus string
	var lastSeenAt any
	var allowedDNSNames string
	var allowedIPAddresses string
	var identityCreatedAt any
	var identityUpdatedAt any
	var issuerKind string
	var issuerStatus string
	var distributionPoints string
	var issuerCreatedAt any
	var issuerUpdatedAt any

	if err := scanner.Scan(
		&record.Certificate.ID,
		&record.Certificate.IdentityID,
		&record.Certificate.IssuerID,
		&record.Certificate.EnrollmentID,
		&record.Certificate.CertificateProfileID,
		&record.Certificate.SerialNumber,
		&record.Certificate.Subject,
		&dnsNames,
		&ipAddresses,
		&notBefore,
		&notAfter,
		&certificateStatus,
		&record.Certificate.CertificatePEM,
		&renewalNotifiedAt,
		&certificateCreatedAt,
		&certificateUpdatedAt,
		&record.Identity.ID,
		&identityType,
		&record.Identity.Name,
		&record.Identity.ExternalID,
		&record.Identity.Owner,
		&record.Identity.Team,
		&record.Identity.Service,
		&record.Identity.Environment,
		&record.Identity.DeploymentTarget,
		&lastSeenAt,
		&record.Identity.MetadataJSON,
		&allowedDNSNames,
		&allowedIPAddresses,
		&identityStatus,
		&identityCreatedAt,
		&identityUpdatedAt,
		&record.Issuer.ID,
		&record.Issuer.Name,
		&issuerKind,
		&issuerStatus,
		&record.Issuer.ParentIssuerID,
		&record.Issuer.CertificatePEM,
		&record.Issuer.KeyRef,
		&record.Issuer.AIAURL,
		&distributionPoints,
		&record.Issuer.TrustAnchor,
		&issuerCreatedAt,
		&issuerUpdatedAt,
	); err != nil {
		return CertificateInventoryRecord{}, err
	}

	var err error
	record.Certificate.DNSNames, err = unmarshalStringSlice(dnsNames)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.IPAddresses, err = unmarshalStringSlice(ipAddresses)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.NotBefore, err = parseSQLTime(notBefore)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.NotAfter, err = parseSQLTime(notAfter)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.RenewalNotifiedAt, err = parseSQLTime(renewalNotifiedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.CreatedAt, err = parseSQLTime(certificateCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.UpdatedAt, err = parseSQLTime(certificateUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Certificate.Status = domain.CertificateStatus(certificateStatus)

	record.Identity.Type = domain.IdentityType(identityType)
	record.Identity.LastSeenAt, err = parseSQLTime(lastSeenAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.AllowedDNSNames, err = unmarshalStringSlice(allowedDNSNames)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.AllowedIPAddresses, err = unmarshalStringSlice(allowedIPAddresses)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.Status = domain.IdentityStatus(identityStatus)
	record.Identity.CreatedAt, err = parseSQLTime(identityCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Identity.UpdatedAt, err = parseSQLTime(identityUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}

	record.Issuer.Kind = domain.IssuerKind(issuerKind)
	record.Issuer.Status = domain.IssuerStatus(issuerStatus)
	record.Issuer.CRLDistributionPoints, err = unmarshalStringSlice(distributionPoints)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Issuer.CreatedAt, err = parseSQLTime(issuerCreatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	record.Issuer.UpdatedAt, err = parseSQLTime(issuerUpdatedAt)
	if err != nil {
		return CertificateInventoryRecord{}, err
	}
	return record, nil
}

func scanIssuanceAttempt(scanner sqlScanner) (domain.IssuanceAttempt, error) {
	var attempt domain.IssuanceAttempt
	var status string
	var leaseExpiresAt any
	var notBefore any
	var notAfter any
	var signingStartedAt any
	var signedAt any
	var finalizedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&attempt.EnrollmentID,
		&status,
		&leaseExpiresAt,
		&attempt.CertificateID,
		&attempt.CertificatePEM,
		&attempt.SerialNumber,
		&attempt.Subject,
		&notBefore,
		&notAfter,
		&signingStartedAt,
		&signedAt,
		&finalizedAt,
		&attempt.LastError,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedLeaseExpiresAt, err := parseSQLTime(leaseExpiresAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedNotBefore, err := parseSQLTime(notBefore)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedNotAfter, err := parseSQLTime(notAfter)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedSigningStartedAt, err := parseSQLTime(signingStartedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedSignedAt, err := parseSQLTime(signedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedFinalizedAt, err := parseSQLTime(finalizedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.IssuanceAttempt{}, err
	}

	attempt.Status = domain.IssuanceAttemptStatus(status)
	attempt.LeaseExpiresAt = parsedLeaseExpiresAt
	attempt.NotBefore = parsedNotBefore
	attempt.NotAfter = parsedNotAfter
	attempt.SigningStartedAt = parsedSigningStartedAt
	attempt.SignedAt = parsedSignedAt
	attempt.FinalizedAt = parsedFinalizedAt
	attempt.CreatedAt = parsedCreatedAt
	attempt.UpdatedAt = parsedUpdatedAt
	return attempt, nil
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
	var processingDeadlineAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&message.ID,
		&message.Type,
		&message.PayloadJSON,
		&status,
		&availableAt,
		&processingDeadlineAt,
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
	parsedProcessingDeadlineAt, err := parseSQLTime(processingDeadlineAt)
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
	message.ProcessingDeadlineAt = parsedProcessingDeadlineAt
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

func scanWebhookDelivery(scanner sqlScanner) (domain.WebhookDelivery, error) {
	var delivery domain.WebhookDelivery
	var status string
	var lastAttemptedAt any
	var createdAt any
	var updatedAt any

	if err := scanner.Scan(
		&delivery.OutboxMessageID,
		&delivery.EndpointID,
		&status,
		&delivery.AttemptCount,
		&delivery.LastError,
		&lastAttemptedAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return domain.WebhookDelivery{}, err
	}

	parsedLastAttemptedAt, err := parseSQLTime(lastAttemptedAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	parsedCreatedAt, err := parseSQLTime(createdAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}
	parsedUpdatedAt, err := parseSQLTime(updatedAt)
	if err != nil {
		return domain.WebhookDelivery{}, err
	}

	delivery.Status = domain.JobAttemptStatus(status)
	delivery.LastAttemptedAt = parsedLastAttemptedAt
	delivery.CreatedAt = parsedCreatedAt
	delivery.UpdatedAt = parsedUpdatedAt
	return delivery, nil
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
	if values == nil {
		values = []string{}
	}
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
		return []string{}, nil
	}

	var values []string
	if err := json.Unmarshal([]byte(data), &values); err != nil {
		return nil, err
	}
	if values == nil {
		return []string{}, nil
	}
	return values, nil
}

func marshalAPIKeyScopes(scopes []domain.APIKeyScope) (string, error) {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, string(scope))
	}
	return marshalStringSlice(values)
}

func unmarshalAPIKeyScopes(data string) ([]domain.APIKeyScope, error) {
	values, err := unmarshalStringSlice(data)
	if err != nil {
		return nil, err
	}
	scopes := make([]domain.APIKeyScope, 0, len(values))
	for _, value := range values {
		scopes = append(scopes, domain.APIKeyScope(value))
	}
	return scopes, nil
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
