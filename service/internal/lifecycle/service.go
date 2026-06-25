package lifecycle

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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

type ACMEHTTP01Verifier interface {
	VerifyHTTP01(ctx context.Context, identifier string, token string, keyAuthorization string) error
}

type ACMEHTTP01VerifierFunc func(ctx context.Context, identifier string, token string, keyAuthorization string) error

func (f ACMEHTTP01VerifierFunc) VerifyHTTP01(ctx context.Context, identifier string, token string, keyAuthorization string) error {
	return f(ctx, identifier, token, keyAuthorization)
}

var acmeHTTP01BlockedSpecialPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
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
	repo               store.Repository
	issuer             CertificateIssuer
	clock              Clock
	idgen              IDGenerator
	acmeHTTP01Verifier ACMEHTTP01Verifier
	apiKeyPepper       string
	productionPolicy   bool
}

type AuditRequestMetadata struct {
	RequestID string
	ClientIP  string
	StartedAt time.Time
}

type APIKeyAuditMetadata struct {
	ID     string
	Name   string
	Scopes []domain.APIKeyScope
}

type APIFailureAuditRequest struct {
	Method     string
	Path       string
	StatusCode int
	Err        error
}

type auditRequestMetadataContextKey struct{}
type apiKeyAuditMetadataContextKey struct{}

type CreateIdentityRequest struct {
	Type               domain.IdentityType
	Name               string
	ExternalID         string
	Owner              string
	MetadataJSON       string
	AllowedDNSNames    []string
	AllowedIPAddresses []string
}

type CreateIssuerRequest struct {
	Name                  string
	Kind                  domain.IssuerKind
	ParentIssuerID        string
	CertificatePEM        string
	KeyRef                string
	AIAURL                string
	CRLDistributionPoints []string
	TrustAnchor           bool
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
	Secret     string
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

type CreateACMEAccountRequest struct {
	Contacts             []string
	TermsOfServiceAgreed bool
	KeyThumbprint        string
	KeyJWKJSON           string
}

type CreateACMEAccountResult struct {
	Account domain.ACMEAccount
	Created bool
}

type UpdateACMEAccountRequest struct {
	Contacts       []string
	UpdateContacts bool
	Deactivate     bool
}

type CreateACMEOrderRequest struct {
	AccountID            string
	IdentityID           string
	IssuerID             string
	CertificateProfileID string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	RequestedNotAfter    time.Time
}

type FinalizeACMEOrderRequest struct {
	CSRPEM           string
	RequestedSubject string
}

const defaultACMEAuthorizationLifetime = 24 * time.Hour

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

type EnsureAPIKeyRequest struct {
	Name   string
	Token  string
	Actor  string
	Scopes []domain.APIKeyScope
}

type CreateAPIKeyRequest struct {
	Name      string
	Actor     string
	Scopes    []domain.APIKeyScope
	ExpiresAt time.Time
}

type CreateAPIKeyResult struct {
	Key   domain.APIKey
	Token string
}

type ocspSigner struct {
	CertificatePEM string
	KeyRef         string
	ResponderMode  string
	ResponderID    string
}

func New(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator) *Service {
	return NewWithACMEHTTP01Verifier(repo, issuer, clock, idgen, nil)
}

func NewWithACMEHTTP01Verifier(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator, verifier ACMEHTTP01Verifier) *Service {
	return NewWithACMEHTTP01VerifierAndAPIKeyPepper(repo, issuer, clock, idgen, verifier, "")
}

func NewWithAPIKeyPepper(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator, pepper string) *Service {
	return NewWithACMEHTTP01VerifierAndAPIKeyPepper(repo, issuer, clock, idgen, nil, pepper)
}

func NewWithACMEHTTP01VerifierAndAPIKeyPepper(repo store.Repository, issuer CertificateIssuer, clock Clock, idgen IDGenerator, verifier ACMEHTTP01Verifier, pepper string) *Service {
	if verifier == nil {
		verifier = defaultACMEHTTP01Verifier()
	}
	return &Service{
		repo:               repo,
		issuer:             issuer,
		clock:              clock,
		idgen:              idgen,
		acmeHTTP01Verifier: verifier,
		apiKeyPepper:       strings.TrimSpace(pepper),
	}
}

func (s *Service) EnableProductionPolicy() {
	s.productionPolicy = true
}

func defaultACMEHTTP01Verifier() ACMEHTTP01Verifier {
	verifier, err := NewACMEHTTP01Verifier("")
	if err != nil {
		panic(err)
	}
	return verifier
}

func NewACMEHTTP01Verifier(overrideBaseURL string) (ACMEHTTP01Verifier, error) {
	var baseURL *url.URL
	overrideBaseURL = strings.TrimSpace(overrideBaseURL)
	if overrideBaseURL != "" {
		parsed, err := url.Parse(overrideBaseURL)
		if err != nil {
			return nil, err
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return nil, fmt.Errorf("scheme must be http or https")
		}
		if parsed.Host == "" {
			return nil, fmt.Errorf("host is required")
		}
		baseURL = parsed
	}
	client := newACMEHTTP01Client(baseURL == nil)
	return ACMEHTTP01VerifierFunc(func(ctx context.Context, identifier string, token string, keyAuthorization string) error {
		challengeURL := acmeHTTP01ChallengeURL(baseURL, identifier, token)
		if baseURL == nil {
			if err := validateACMEHTTP01FetchURL(&challengeURL); err != nil {
				return err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, challengeURL.String(), nil)
		if err != nil {
			return err
		}
		res, err := client.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return domain.ErrInvalidRequest
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(body)) != keyAuthorization {
			return domain.ErrInvalidRequest
		}
		return nil
	}), nil
}

func newACMEHTTP01Client(guardTargets bool) *http.Client {
	client := &http.Client{Timeout: 10 * time.Second}
	if !guardTargets {
		return client
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return domain.ErrInvalidRequest
		}
		return validateACMEHTTP01FetchURL(req.URL)
	}
	client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, domain.ErrInvalidRequest
			}
			if err := validateACMEHTTP01Host(host); err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{}
			var lastErr error
			for _, ip := range ips {
				addr, ok := netip.AddrFromSlice(ip.IP)
				if !ok {
					continue
				}
				addr = addr.Unmap()
				if !acmeHTTP01SafeIP(addr) {
					continue
				}
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, domain.ErrInvalidRequest
		},
	}
	return client
}

func validateACMEHTTP01FetchURL(fetchURL *url.URL) error {
	if fetchURL == nil ||
		(fetchURL.Scheme != "http" && fetchURL.Scheme != "https") ||
		fetchURL.Host == "" ||
		fetchURL.User != nil {
		return domain.ErrInvalidRequest
	}
	return validateACMEHTTP01Host(fetchURL.Hostname())
}

func validateACMEHTTP01Host(host string) error {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return domain.ErrInvalidRequest
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !acmeHTTP01SafeIP(addr.Unmap()) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func acmeHTTP01SafeIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if acmeHTTP01BlockedSpecialIP(addr) {
		return false
	}
	return !addr.IsLoopback() &&
		!addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

func acmeHTTP01BlockedSpecialIP(addr netip.Addr) bool {
	for _, prefix := range acmeHTTP01BlockedSpecialPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return addr == netip.MustParseAddr("169.254.169.254") ||
		addr == netip.MustParseAddr("100.100.100.200")
}

func acmeHTTP01ChallengeURL(baseURL *url.URL, identifier string, token string) url.URL {
	challengePath := "/.well-known/acme-challenge/" + token
	if baseURL == nil {
		return url.URL{
			Scheme: "http",
			Host:   identifier,
			Path:   challengePath,
		}
	}
	challengeURL := *baseURL
	challengeURL.Path = strings.TrimRight(challengeURL.Path, "/") + challengePath
	challengeURL.RawQuery = ""
	challengeURL.Fragment = ""
	return challengeURL
}

func WithAuditRequestMetadata(ctx context.Context, metadata AuditRequestMetadata) context.Context {
	return context.WithValue(ctx, auditRequestMetadataContextKey{}, metadata)
}

func WithAPIKeyAuditMetadata(ctx context.Context, metadata APIKeyAuditMetadata) context.Context {
	return context.WithValue(ctx, apiKeyAuditMetadataContextKey{}, metadata)
}

func HashAPIKeyToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HashAPIKeyTokenWithPepper(token string, pepper string) string {
	pepper = strings.TrimSpace(pepper)
	if pepper == "" {
		return HashAPIKeyToken(token)
	}
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(token))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func APIKeyTokenFingerprint(tokenHash string) string {
	algorithm, hash, ok := strings.Cut(tokenHash, ":")
	if !ok || algorithm == "" || hash == "" {
		return ""
	}
	if len(hash) > 16 {
		hash = hash[:16]
	}
	return algorithm + ":" + hash
}

func (s *Service) AuthenticateAPIKey(ctx context.Context, token string) (domain.APIKey, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return domain.APIKey{}, domain.ErrUnauthorized
	}

	key, err := s.getAPIKeyByToken(ctx, token)
	if errors.Is(err, domain.ErrAPIKeyNotFound) {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.APIKey{}, err
	}
	if key.Status != domain.APIKeyActive || strings.TrimSpace(key.Actor) == "" {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	if len(key.Scopes) == 0 {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	now := s.clock.Now()
	if !key.ExpiresAt.IsZero() && !key.ExpiresAt.After(now) {
		return domain.APIKey{}, domain.ErrUnauthorized
	}
	key.LastUsedAt = now
	key.UpdatedAt = now
	if err := s.repo.UpdateAPIKeyIfStatus(ctx, key, domain.APIKeyActive); err != nil {
		if errors.Is(err, domain.ErrAPIKeyNotFound) || errors.Is(err, domain.ErrInvalidTransition) {
			return domain.APIKey{}, domain.ErrUnauthorized
		}
		return domain.APIKey{}, err
	}
	return key, nil
}

func (s *Service) hashAPIKeyToken(token string) string {
	return HashAPIKeyTokenWithPepper(token, s.apiKeyPepper)
}

func (s *Service) getAPIKeyByToken(ctx context.Context, token string) (domain.APIKey, error) {
	if strings.TrimSpace(s.apiKeyPepper) != "" {
		key, err := s.repo.GetAPIKeyByTokenHash(ctx, s.hashAPIKeyToken(token))
		if err == nil || !errors.Is(err, domain.ErrAPIKeyNotFound) {
			return key, err
		}
	}
	return s.repo.GetAPIKeyByTokenHash(ctx, HashAPIKeyToken(token))
}

func (s *Service) EnsureAPIKey(ctx context.Context, actor string, req EnsureAPIKeyRequest) (domain.APIKey, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Token) == "" || strings.TrimSpace(req.Actor) == "" {
		return domain.APIKey{}, domain.ErrInvalidRequest
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []domain.APIKeyScope{domain.APIKeyScopeOperator}
	}
	if err := validateAPIKeyScopes(scopes); err != nil {
		return domain.APIKey{}, err
	}

	tokenHash := s.hashAPIKeyToken(req.Token)
	existing, err := s.getAPIKeyByToken(ctx, req.Token)
	if err == nil {
		if existing.Status != domain.APIKeyActive || strings.TrimSpace(existing.Actor) == "" || len(existing.Scopes) == 0 {
			return domain.APIKey{}, domain.ErrInvalidTransition
		}
		if err := validateAPIKeyScopes(existing.Scopes); err != nil {
			return domain.APIKey{}, err
		}
		hasOperatorScope := false
		for _, scope := range existing.Scopes {
			if scope == domain.APIKeyScopeOperator {
				hasOperatorScope = true
				break
			}
		}
		if !hasOperatorScope {
			return domain.APIKey{}, domain.ErrInvalidTransition
		}
		return existing, nil
	}
	if !errors.Is(err, domain.ErrAPIKeyNotFound) {
		return domain.APIKey{}, err
	}

	now := s.clock.Now()
	key := domain.APIKey{
		ID:        s.idgen.NewID(),
		Name:      strings.TrimSpace(req.Name),
		TokenHash: tokenHash,
		Status:    domain.APIKeyActive,
		Actor:     strings.TrimSpace(req.Actor),
		Scopes:    append([]domain.APIKeyScope(nil), scopes...),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateAPIKey(ctx, key); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "api_key.created", "api_key", key.ID, now, auditFields(
			"api_key_id", key.ID,
			"api_key_name", key.Name,
			"api_key_actor", key.Actor,
		))
	}); err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (s *Service) CreateAPIKey(ctx context.Context, actor string, req CreateAPIKeyRequest) (CreateAPIKeyResult, error) {
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Actor) == "" || len(req.Scopes) == 0 {
		return CreateAPIKeyResult{}, domain.ErrInvalidRequest
	}
	if err := validateAPIKeyScopes(req.Scopes); err != nil {
		return CreateAPIKeyResult{}, err
	}
	now := s.clock.Now()
	if !req.ExpiresAt.IsZero() && !req.ExpiresAt.After(now) {
		return CreateAPIKeyResult{}, domain.ErrInvalidRequest
	}
	token, err := generateAPIKeyToken()
	if err != nil {
		return CreateAPIKeyResult{}, err
	}

	key := domain.APIKey{
		ID:        s.idgen.NewID(),
		Name:      strings.TrimSpace(req.Name),
		TokenHash: s.hashAPIKeyToken(token),
		Status:    domain.APIKeyActive,
		Actor:     strings.TrimSpace(req.Actor),
		Scopes:    append([]domain.APIKeyScope(nil), req.Scopes...),
		ExpiresAt: req.ExpiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateAPIKey(ctx, key); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "api_key.created", "api_key", key.ID, now, apiKeyAuditFields(key))
	}); err != nil {
		return CreateAPIKeyResult{}, err
	}
	return CreateAPIKeyResult{Key: key, Token: token}, nil
}

func (s *Service) ListAPIKeys(ctx context.Context) ([]domain.APIKey, error) {
	return s.repo.ListAPIKeys(ctx)
}

func (s *Service) DisableAPIKey(ctx context.Context, actor string, id string) (domain.APIKey, error) {
	if isBlank(id) {
		return domain.APIKey{}, domain.ErrInvalidRequest
	}
	now := s.clock.Now()
	var key domain.APIKey
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		var err error
		key, err = repo.GetAPIKey(ctx, id)
		if err != nil {
			return err
		}
		if key.Status != domain.APIKeyActive {
			return domain.ErrInvalidTransition
		}
		key.Status = domain.APIKeyDisabled
		key.UpdatedAt = now
		if err := repo.UpdateAPIKeyIfStatus(ctx, key, domain.APIKeyActive); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "api_key.disabled", "api_key", key.ID, now, apiKeyAuditFields(key))
	}); err != nil {
		return domain.APIKey{}, err
	}
	return key, nil
}

func (s *Service) RotateAPIKey(ctx context.Context, actor string, id string) (CreateAPIKeyResult, error) {
	if isBlank(id) {
		return CreateAPIKeyResult{}, domain.ErrInvalidRequest
	}
	token, err := generateAPIKeyToken()
	if err != nil {
		return CreateAPIKeyResult{}, err
	}
	now := s.clock.Now()
	var newKey domain.APIKey
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		oldKey, err := repo.GetAPIKey(ctx, id)
		if err != nil {
			return err
		}
		if oldKey.Status != domain.APIKeyActive || (!oldKey.ExpiresAt.IsZero() && !oldKey.ExpiresAt.After(now)) {
			return domain.ErrInvalidTransition
		}
		oldKey.Status = domain.APIKeyDisabled
		oldKey.UpdatedAt = now
		if err := repo.UpdateAPIKeyIfStatus(ctx, oldKey, domain.APIKeyActive); err != nil {
			return err
		}

		newKey = domain.APIKey{
			ID:        s.idgen.NewID(),
			Name:      oldKey.Name,
			TokenHash: s.hashAPIKeyToken(token),
			Status:    domain.APIKeyActive,
			Actor:     oldKey.Actor,
			Scopes:    append([]domain.APIKeyScope(nil), oldKey.Scopes...),
			ExpiresAt: oldKey.ExpiresAt,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := repo.CreateAPIKey(ctx, newKey); err != nil {
			return err
		}
		fields := apiKeyAuditFields(newKey)
		fields["rotated_from_api_key_id"] = oldKey.ID
		return s.createAuditEvent(ctx, repo, actor, "api_key.rotated", "api_key", newKey.ID, now, fields)
	}); err != nil {
		return CreateAPIKeyResult{}, err
	}
	return CreateAPIKeyResult{Key: newKey, Token: token}, nil
}

func (s *Service) CreateIdentity(ctx context.Context, actor string, req CreateIdentityRequest) (domain.Identity, error) {
	if err := validateCreateIdentityRequest(req); err != nil {
		return domain.Identity{}, err
	}

	now := s.clock.Now()
	identity := domain.Identity{
		ID:                 s.idgen.NewID(),
		Type:               req.Type,
		Name:               req.Name,
		ExternalID:         req.ExternalID,
		Owner:              req.Owner,
		MetadataJSON:       req.MetadataJSON,
		AllowedDNSNames:    copyStringSlice(req.AllowedDNSNames),
		AllowedIPAddresses: copyStringSlice(req.AllowedIPAddresses),
		Status:             domain.IdentityActive,
		CreatedAt:          now,
		UpdatedAt:          now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateIdentity(ctx, identity); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "identity.created", "identity", identity.ID, now, auditFields(
			"identity_id", identity.ID,
			"owner", identity.Owner,
			"allowed_dns_names", fmt.Sprintf("%d", len(identity.AllowedDNSNames)),
			"allowed_ip_addresses", fmt.Sprintf("%d", len(identity.AllowedIPAddresses)),
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
		ID:                    s.idgen.NewID(),
		Name:                  req.Name,
		Kind:                  req.Kind,
		Status:                domain.IssuerActive,
		ParentIssuerID:        req.ParentIssuerID,
		CertificatePEM:        req.CertificatePEM,
		KeyRef:                req.KeyRef,
		AIAURL:                req.AIAURL,
		CRLDistributionPoints: append([]string(nil), req.CRLDistributionPoints...),
		TrustAnchor:           req.TrustAnchor || req.Kind == domain.IssuerRootCA,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if req.ParentIssuerID != "" {
			if _, err := repo.GetIssuer(ctx, req.ParentIssuerID); err != nil {
				return err
			}
		}
		if err := repo.CreateIssuer(ctx, issuer); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "issuer.created", "issuer", issuer.ID, now, auditFields(
			"issuer_id", issuer.ID,
			"parent_issuer_id", issuer.ParentIssuerID,
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
	if err := validateCreateNotificationEndpointRequest(req, s.productionPolicy); err != nil {
		return domain.NotificationEndpoint{}, err
	}

	now := s.clock.Now()
	endpoint := domain.NotificationEndpoint{
		ID:         s.idgen.NewID(),
		Name:       req.Name,
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        req.URL,
		Secret:     req.Secret,
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

func (s *Service) GetIssuerChain(ctx context.Context, id string) ([]domain.Issuer, error) {
	if isBlank(id) {
		return nil, domain.ErrInvalidRequest
	}
	chain := make([]domain.Issuer, 0)
	seen := make(map[string]struct{})
	currentID := id
	for currentID != "" {
		if _, ok := seen[currentID]; ok {
			return nil, domain.ErrInvalidRequest
		}
		seen[currentID] = struct{}{}
		issuer, err := s.repo.GetIssuer(ctx, currentID)
		if err != nil {
			return nil, err
		}
		chain = append(chain, issuer)
		currentID = issuer.ParentIssuerID
	}
	return chain, nil
}

func (s *Service) ListTrustAnchors(ctx context.Context) ([]domain.Issuer, error) {
	issuers, err := s.repo.ListIssuers(ctx)
	if err != nil {
		return nil, err
	}
	anchors := make([]domain.Issuer, 0)
	for _, issuer := range issuers {
		if issuer.Status == domain.IssuerActive && issuer.TrustAnchor {
			anchors = append(anchors, issuer)
		}
	}
	return anchors, nil
}

func (s *Service) CreateACMEAccount(ctx context.Context, actor string, req CreateACMEAccountRequest) (domain.ACMEAccount, error) {
	if err := validateCreateACMEAccountRequest(req); err != nil {
		return domain.ACMEAccount{}, err
	}
	return s.createACMEAccount(ctx, actor, req)
}

func (s *Service) CreateOrGetACMEAccount(ctx context.Context, actor string, req CreateACMEAccountRequest) (CreateACMEAccountResult, error) {
	if err := validateCreateACMEAccountRequest(req); err != nil {
		return CreateACMEAccountResult{}, err
	}
	keyThumbprint := strings.TrimSpace(req.KeyThumbprint)
	if keyThumbprint != "" {
		accounts, err := s.repo.ListACMEAccounts(ctx)
		if err != nil {
			return CreateACMEAccountResult{}, err
		}
		for _, account := range accounts {
			if account.KeyThumbprint == keyThumbprint {
				return CreateACMEAccountResult{Account: account}, nil
			}
		}
	}
	account, err := s.createACMEAccount(ctx, actor, req)
	if err != nil {
		return CreateACMEAccountResult{}, err
	}
	return CreateACMEAccountResult{Account: account, Created: true}, nil
}

func (s *Service) createACMEAccount(ctx context.Context, actor string, req CreateACMEAccountRequest) (domain.ACMEAccount, error) {
	now := s.clock.Now()
	account := domain.ACMEAccount{
		ID:                   s.idgen.NewID(),
		Contacts:             append([]string(nil), req.Contacts...),
		Status:               domain.ACMEAccountValid,
		TermsOfServiceAgreed: req.TermsOfServiceAgreed,
		KeyThumbprint:        strings.TrimSpace(req.KeyThumbprint),
		KeyJWKJSON:           strings.TrimSpace(req.KeyJWKJSON),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.CreateACMEAccount(ctx, account); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.account.created", "acme_account", account.ID, now, auditFields(
			"acme_account_id", account.ID,
		))
	}); err != nil {
		return domain.ACMEAccount{}, err
	}
	return account, nil
}

func (s *Service) UpdateACMEAccount(ctx context.Context, actor string, accountID string, req UpdateACMEAccountRequest) (domain.ACMEAccount, error) {
	if isBlank(accountID) || (!req.UpdateContacts && !req.Deactivate) {
		return domain.ACMEAccount{}, domain.ErrInvalidRequest
	}
	now := s.clock.Now()
	var updated domain.ACMEAccount
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		account, err := repo.GetACMEAccount(ctx, accountID)
		if err != nil {
			return err
		}
		if account.Status == domain.ACMEAccountDeactivated {
			return domain.ErrACMEAccountDeactivated
		}
		if account.Status != domain.ACMEAccountValid {
			return domain.ErrInvalidTransition
		}
		if req.UpdateContacts {
			account.Contacts = append([]string(nil), req.Contacts...)
		}
		if req.Deactivate {
			account.Status = domain.ACMEAccountDeactivated
		}
		account.UpdatedAt = now
		if err := repo.UpdateACMEAccountIfStatus(ctx, account, domain.ACMEAccountValid); err != nil {
			return err
		}
		updated = account
		action := "acme.account.updated"
		if req.Deactivate {
			action = "acme.account.deactivated"
		}
		return s.createAuditEvent(ctx, repo, actor, action, "acme_account", account.ID, now, auditFields(
			"acme_account_id", account.ID,
		))
	}); err != nil {
		return domain.ACMEAccount{}, err
	}
	return updated, nil
}

func (s *Service) CreateACMEOrder(ctx context.Context, actor string, req CreateACMEOrderRequest) (domain.ACMEOrder, error) {
	now := s.clock.Now()
	if err := validateCreateACMEOrderRequest(req, now); err != nil {
		return domain.ACMEOrder{}, err
	}
	order := domain.ACMEOrder{
		ID:                   s.idgen.NewID(),
		AccountID:            req.AccountID,
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CertificateProfileID: req.CertificateProfileID,
		Status:               domain.ACMEOrderPending,
		RequestedDNSNames:    append([]string(nil), req.RequestedDNSNames...),
		RequestedIPAddresses: append([]string(nil), req.RequestedIPAddresses...),
		RequestedNotAfter:    req.RequestedNotAfter,
		ExpiresAt:            now.Add(defaultACMEAuthorizationLifetime),
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		account, err := repo.GetACMEAccount(ctx, req.AccountID)
		if err != nil {
			return err
		}
		if account.Status == domain.ACMEAccountDeactivated {
			return domain.ErrACMEAccountDeactivated
		}
		if account.Status != domain.ACMEAccountValid {
			return domain.ErrInvalidRequest
		}
		identity, err := repo.GetIdentity(ctx, req.IdentityID)
		if err != nil {
			return err
		}
		if err := validateEnrollmentIdentityPolicy(CreateEnrollmentRequest{
			IdentityID:           req.IdentityID,
			IssuerID:             req.IssuerID,
			CertificateProfileID: req.CertificateProfileID,
			RequestedDNSNames:    req.RequestedDNSNames,
			RequestedIPAddresses: req.RequestedIPAddresses,
			RequestedNotAfter:    req.RequestedNotAfter,
		}, identity); err != nil {
			return err
		}
		if _, err := repo.GetIssuer(ctx, req.IssuerID); err != nil {
			return err
		}
		if req.CertificateProfileID != "" {
			if _, err := repo.GetCertificateProfile(ctx, req.CertificateProfileID); err != nil {
				return err
			}
		}
		if err := repo.CreateACMEOrder(ctx, order); err != nil {
			return err
		}
		if err := s.createACMEAuthorizations(ctx, repo, order, now); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.order.created", "acme_order", order.ID, now, auditFields(
			"acme_account_id", order.AccountID,
			"acme_order_id", order.ID,
			"identity_id", order.IdentityID,
			"issuer_id", order.IssuerID,
			"profile_id", order.CertificateProfileID,
		))
	}); err != nil {
		return domain.ACMEOrder{}, err
	}
	return order, nil
}

func (s *Service) GetACMEOrder(ctx context.Context, id string) (domain.ACMEOrder, error) {
	if isBlank(id) {
		return domain.ACMEOrder{}, domain.ErrInvalidRequest
	}
	return s.repo.GetACMEOrder(ctx, id)
}

func (s *Service) ListACMEAccounts(ctx context.Context) ([]domain.ACMEAccount, error) {
	return s.repo.ListACMEAccounts(ctx)
}

func (s *Service) GetACMEAccount(ctx context.Context, id string) (domain.ACMEAccount, error) {
	if isBlank(id) {
		return domain.ACMEAccount{}, domain.ErrInvalidRequest
	}
	return s.repo.GetACMEAccount(ctx, id)
}

func (s *Service) ListACMEOrdersByAccount(ctx context.Context, accountID string) ([]domain.ACMEOrder, error) {
	if isBlank(accountID) {
		return nil, domain.ErrInvalidRequest
	}
	return s.repo.ListACMEOrdersByAccount(ctx, accountID)
}

func (s *Service) ListACMEAuthorizations(ctx context.Context, orderID string) ([]domain.ACMEAuthorization, error) {
	if isBlank(orderID) {
		return nil, domain.ErrInvalidRequest
	}
	if _, err := s.repo.GetACMEOrder(ctx, orderID); err != nil {
		return nil, err
	}
	return s.repo.ListACMEAuthorizationsByOrder(ctx, orderID)
}

func (s *Service) GetACMEAuthorization(ctx context.Context, id string) (domain.ACMEAuthorization, error) {
	if isBlank(id) {
		return domain.ACMEAuthorization{}, domain.ErrInvalidRequest
	}
	return s.repo.GetACMEAuthorization(ctx, id)
}

func (s *Service) PollACMEAuthorization(ctx context.Context, actor string, authorizationID string) (domain.ACMEAuthorization, error) {
	if isBlank(authorizationID) {
		return domain.ACMEAuthorization{}, domain.ErrInvalidRequest
	}
	authorization, err := s.repo.GetACMEAuthorization(ctx, authorizationID)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	if authorization.Status != domain.ACMEAuthorizationPending {
		return authorization, nil
	}
	challenges, err := s.repo.ListACMEChallengesByAuthorization(ctx, authorizationID)
	if err != nil {
		return domain.ACMEAuthorization{}, err
	}
	for _, challenge := range challenges {
		if challenge.Type == domain.ACMEChallengeHTTP01 && challenge.Status == domain.ACMEChallengeProcessing {
			if _, err := s.ValidateACMEHTTP01Challenge(ctx, actor, challenge.ID); err != nil {
				return domain.ACMEAuthorization{}, err
			}
		}
	}
	return s.repo.GetACMEAuthorization(ctx, authorizationID)
}

func (s *Service) ListACMEChallenges(ctx context.Context, authorizationID string) ([]domain.ACMEChallenge, error) {
	if isBlank(authorizationID) {
		return nil, domain.ErrInvalidRequest
	}
	if _, err := s.repo.GetACMEAuthorization(ctx, authorizationID); err != nil {
		return nil, err
	}
	return s.repo.ListACMEChallengesByAuthorization(ctx, authorizationID)
}

func (s *Service) GetACMEChallenge(ctx context.Context, id string) (domain.ACMEChallenge, error) {
	if isBlank(id) {
		return domain.ACMEChallenge{}, domain.ErrInvalidRequest
	}
	return s.repo.GetACMEChallenge(ctx, id)
}

func (s *Service) CompleteACMEChallenge(ctx context.Context, actor string, challengeID string) (domain.ACMEChallenge, error) {
	if isBlank(challengeID) {
		return domain.ACMEChallenge{}, domain.ErrInvalidRequest
	}
	now := s.clock.Now()
	var completed domain.ACMEChallenge
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		challenge, err := repo.GetACMEChallenge(ctx, challengeID)
		if err != nil {
			return err
		}
		if challenge.Status != domain.ACMEChallengePending && challenge.Status != domain.ACMEChallengeProcessing {
			return domain.ErrInvalidTransition
		}
		currentStatus := challenge.Status
		authorization, err := repo.GetACMEAuthorization(ctx, challenge.AuthorizationID)
		if err != nil {
			return err
		}
		if authorization.Status != domain.ACMEAuthorizationPending {
			return domain.ErrInvalidTransition
		}
		challenge.Status = domain.ACMEChallengeValid
		challenge.ValidatedAt = now
		challenge.UpdatedAt = now
		if err := repo.UpdateACMEChallengeIfStatus(ctx, challenge, currentStatus); err != nil {
			return err
		}
		completed = challenge
		if err := s.promoteACMEAuthorizationIfReady(ctx, repo, authorization, now); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.challenge.completed", "acme_challenge", challenge.ID, now, auditFields(
			"acme_challenge_id", challenge.ID,
			"acme_authorization_id", authorization.ID,
			"acme_order_id", authorization.OrderID,
		))
	}); err != nil {
		return domain.ACMEChallenge{}, err
	}
	return completed, nil
}

func (s *Service) ValidateACMEHTTP01Challenge(ctx context.Context, actor string, challengeID string) (domain.ACMEChallenge, error) {
	validation, err := s.acmeHTTP01ValidationContext(ctx, challengeID)
	if err != nil {
		return domain.ACMEChallenge{}, err
	}
	if err := s.acmeHTTP01Verifier.VerifyHTTP01(ctx, validation.IdentifierValue, validation.Challenge.Token, validation.KeyAuthorization); err != nil {
		return s.markACMEChallengeProcessing(ctx, actor, validation.Challenge.ID)
	}
	return s.CompleteACMEChallenge(ctx, actor, challengeID)
}

func (s *Service) FinalizeACMEOrder(ctx context.Context, actor string, orderID string, req FinalizeACMEOrderRequest) (domain.ACMEOrder, error) {
	if isBlank(orderID) || isBlank(req.CSRPEM) || isBlank(req.RequestedSubject) {
		return domain.ACMEOrder{}, domain.ErrInvalidRequest
	}
	order, err := s.repo.GetACMEOrder(ctx, orderID)
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	if order.Status == domain.ACMEOrderValid {
		return order, nil
	}
	if order.Status != domain.ACMEOrderReady {
		return domain.ACMEOrder{}, domain.ErrInvalidTransition
	}
	if acmeExpired(order.ExpiresAt, s.clock.Now()) {
		if err := s.invalidateACMEOrder(ctx, actor, order); err != nil {
			return domain.ACMEOrder{}, err
		}
		return domain.ACMEOrder{}, domain.ErrInvalidTransition
	}

	enrollment, err := s.CreateEnrollment(ctx, actor, CreateEnrollmentRequest{
		IdentityID:           order.IdentityID,
		IssuerID:             order.IssuerID,
		CertificateProfileID: order.CertificateProfileID,
		CSRPEM:               req.CSRPEM,
		RequestedSubject:     req.RequestedSubject,
		RequestedDNSNames:    append([]string(nil), order.RequestedDNSNames...),
		RequestedIPAddresses: append([]string(nil), order.RequestedIPAddresses...),
		RequestedNotAfter:    order.RequestedNotAfter,
	})
	if err != nil {
		return domain.ACMEOrder{}, err
	}
	if _, err := s.ApproveEnrollment(ctx, actor, enrollment.ID); err != nil {
		return domain.ACMEOrder{}, err
	}
	certificate, err := s.IssueCertificate(ctx, actor, enrollment.ID)
	if err != nil {
		return domain.ACMEOrder{}, err
	}

	now := s.clock.Now()
	order.CSRPEM = req.CSRPEM
	order.RequestedSubject = req.RequestedSubject
	order.EnrollmentID = enrollment.ID
	order.CertificateID = certificate.ID
	order.Status = domain.ACMEOrderValid
	order.UpdatedAt = now
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderReady); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.order.finalized", "acme_order", order.ID, now, auditFields(
			"acme_account_id", order.AccountID,
			"acme_order_id", order.ID,
			"enrollment_id", enrollment.ID,
			"certificate_id", certificate.ID,
		))
	}); err != nil {
		return domain.ACMEOrder{}, err
	}
	return order, nil
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
	message.ProcessingDeadlineAt = time.Time{}
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

	identity, err := s.repo.GetIdentity(ctx, req.IdentityID)
	if err != nil {
		return domain.Enrollment{}, err
	}
	if _, err := s.repo.GetIssuer(ctx, req.IssuerID); err != nil {
		return domain.Enrollment{}, err
	}
	var profile domain.CertificateProfile
	if req.CertificateProfileID != "" {
		var err error
		profile, err = s.repo.GetCertificateProfile(ctx, req.CertificateProfileID)
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
	if err := validateEnrollmentProfilePolicy(req, profile, now); err != nil {
		return domain.Enrollment{}, err
	}
	if err := validateEnrollmentIdentityPolicy(req, identity); err != nil {
		return domain.Enrollment{}, err
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
	var profile domain.CertificateProfile
	if createReq.CertificateProfileID != "" {
		var err error
		profile, err = s.repo.GetCertificateProfile(ctx, createReq.CertificateProfileID)
		if err != nil {
			return domain.Enrollment{}, err
		}
		if profile.IssuerID != createReq.IssuerID {
			return domain.Enrollment{}, domain.ErrInvalidRequest
		}
	}
	if err := validateEnrollmentProfilePolicy(createReq, profile, now); err != nil {
		return domain.Enrollment{}, err
	}
	identity, err := s.repo.GetIdentity(ctx, createReq.IdentityID)
	if err != nil {
		return domain.Enrollment{}, err
	}
	if err := validateEnrollmentIdentityPolicy(createReq, identity); err != nil {
		return domain.Enrollment{}, err
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
	if enrollment.Status == domain.EnrollmentIssued {
		certificate, err := s.repo.GetCertificateByEnrollmentID(ctx, enrollmentID)
		if err == nil {
			return certificate, nil
		}
		if !errors.Is(err, domain.ErrCertificateNotFound) {
			return domain.Certificate{}, err
		}
		return domain.Certificate{}, domain.ErrInvalidTransition
	}
	if enrollment.Status != domain.EnrollmentApproved {
		return domain.Certificate{}, domain.ErrInvalidTransition
	}

	issuer, err := s.repo.GetIssuer(ctx, enrollment.IssuerID)
	if err != nil {
		return domain.Certificate{}, err
	}
	identity, err := s.repo.GetIdentity(ctx, enrollment.IdentityID)
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
	if err := validateEnrollmentProfilePolicy(enrollmentProfilePolicyRequest(enrollment), profile, now); err != nil {
		return domain.Certificate{}, err
	}
	if err := validateEnrollmentIdentityPolicy(enrollmentProfilePolicyRequest(enrollment), identity); err != nil {
		return domain.Certificate{}, err
	}
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
		if errors.Is(err, domain.ErrInvalidTransition) {
			existing, lookupErr := s.repo.GetCertificateByEnrollmentID(ctx, enrollmentID)
			if lookupErr == nil {
				return existing, nil
			}
			if !errors.Is(lookupErr, domain.ErrCertificateNotFound) {
				return domain.Certificate{}, lookupErr
			}
		}
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

func (s *Service) createACMEAuthorizations(ctx context.Context, repo store.Repository, order domain.ACMEOrder, now time.Time) error {
	for _, dnsName := range order.RequestedDNSNames {
		if err := s.createACMEAuthorization(ctx, repo, order.ID, "dns", dnsName, domain.ACMEChallengeHTTP01, now); err != nil {
			return err
		}
	}
	for _, ipAddress := range order.RequestedIPAddresses {
		if err := s.createACMEAuthorization(ctx, repo, order.ID, "ip", ipAddress, domain.ACMEChallengeHTTP01, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) createACMEAuthorization(ctx context.Context, repo store.Repository, orderID string, identifierType string, identifierValue string, challengeType domain.ACMEChallengeType, now time.Time) error {
	authorization := domain.ACMEAuthorization{
		ID:              s.idgen.NewID(),
		OrderID:         orderID,
		IdentifierType:  identifierType,
		IdentifierValue: identifierValue,
		Status:          domain.ACMEAuthorizationPending,
		ExpiresAt:       now.Add(defaultACMEAuthorizationLifetime),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := repo.CreateACMEAuthorization(ctx, authorization); err != nil {
		return err
	}
	return repo.CreateACMEChallenge(ctx, domain.ACMEChallenge{
		ID:              s.idgen.NewID(),
		AuthorizationID: authorization.ID,
		Type:            challengeType,
		Token:           s.idgen.NewID(),
		Status:          domain.ACMEChallengePending,
		CreatedAt:       now,
		UpdatedAt:       now,
	})
}

type acmeHTTP01ValidationContext struct {
	Challenge        domain.ACMEChallenge
	IdentifierValue  string
	KeyAuthorization string
}

func (s *Service) acmeHTTP01ValidationContext(ctx context.Context, challengeID string) (acmeHTTP01ValidationContext, error) {
	if isBlank(challengeID) {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidRequest
	}
	challenge, err := s.repo.GetACMEChallenge(ctx, challengeID)
	if err != nil {
		return acmeHTTP01ValidationContext{}, err
	}
	if challenge.Type != domain.ACMEChallengeHTTP01 ||
		(challenge.Status != domain.ACMEChallengePending && challenge.Status != domain.ACMEChallengeProcessing) {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidTransition
	}
	authorization, err := s.repo.GetACMEAuthorization(ctx, challenge.AuthorizationID)
	if err != nil {
		return acmeHTTP01ValidationContext{}, err
	}
	if authorization.Status != domain.ACMEAuthorizationPending {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidTransition
	}
	order, err := s.repo.GetACMEOrder(ctx, authorization.OrderID)
	if err != nil {
		return acmeHTTP01ValidationContext{}, err
	}
	if order.Status != domain.ACMEOrderPending {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidTransition
	}
	now := s.clock.Now()
	if acmeExpired(order.ExpiresAt, now) || acmeExpired(authorization.ExpiresAt, now) {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidTransition
	}
	account, err := s.repo.GetACMEAccount(ctx, order.AccountID)
	if err != nil {
		return acmeHTTP01ValidationContext{}, err
	}
	if account.Status == domain.ACMEAccountDeactivated {
		return acmeHTTP01ValidationContext{}, domain.ErrACMEAccountDeactivated
	}
	if account.Status != domain.ACMEAccountValid || account.KeyThumbprint == "" {
		return acmeHTTP01ValidationContext{}, domain.ErrInvalidRequest
	}
	return acmeHTTP01ValidationContext{
		Challenge:        challenge,
		IdentifierValue:  authorization.IdentifierValue,
		KeyAuthorization: challenge.Token + "." + account.KeyThumbprint,
	}, nil
}

func (s *Service) markACMEChallengeProcessing(ctx context.Context, actor string, challengeID string) (domain.ACMEChallenge, error) {
	now := s.clock.Now()
	var processing domain.ACMEChallenge
	if err := s.repo.WithinTx(ctx, func(repo store.Repository) error {
		challenge, err := repo.GetACMEChallenge(ctx, challengeID)
		if err != nil {
			return err
		}
		if challenge.Status != domain.ACMEChallengePending && challenge.Status != domain.ACMEChallengeProcessing {
			return domain.ErrInvalidTransition
		}
		currentStatus := challenge.Status
		authorization, err := repo.GetACMEAuthorization(ctx, challenge.AuthorizationID)
		if err != nil {
			return err
		}
		if authorization.Status != domain.ACMEAuthorizationPending {
			return domain.ErrInvalidTransition
		}
		challenge.Status = domain.ACMEChallengeProcessing
		challenge.UpdatedAt = now
		if err := repo.UpdateACMEChallengeIfStatus(ctx, challenge, currentStatus); err != nil {
			return err
		}
		processing = challenge
		return s.createAuditEvent(ctx, repo, actor, "acme.challenge.processing", "acme_challenge", challenge.ID, now, auditFields(
			"acme_challenge_id", challenge.ID,
			"acme_authorization_id", authorization.ID,
			"acme_order_id", authorization.OrderID,
		))
	}); err != nil {
		return domain.ACMEChallenge{}, err
	}
	return processing, nil
}

func (s *Service) invalidateACMEChallenge(ctx context.Context, actor string, challengeID string) error {
	now := s.clock.Now()
	return s.repo.WithinTx(ctx, func(repo store.Repository) error {
		challenge, err := repo.GetACMEChallenge(ctx, challengeID)
		if err != nil {
			return err
		}
		if challenge.Status != domain.ACMEChallengePending {
			return domain.ErrInvalidTransition
		}
		authorization, err := repo.GetACMEAuthorization(ctx, challenge.AuthorizationID)
		if err != nil {
			return err
		}
		order, err := repo.GetACMEOrder(ctx, authorization.OrderID)
		if err != nil {
			return err
		}
		challenge.Status = domain.ACMEChallengeInvalid
		challenge.UpdatedAt = now
		if err := repo.UpdateACMEChallengeIfStatus(ctx, challenge, domain.ACMEChallengePending); err != nil {
			return err
		}
		if authorization.Status == domain.ACMEAuthorizationPending {
			authorization.Status = domain.ACMEAuthorizationInvalid
			authorization.UpdatedAt = now
			if err := repo.UpdateACMEAuthorizationIfStatus(ctx, authorization, domain.ACMEAuthorizationPending); err != nil {
				return err
			}
		}
		if order.Status == domain.ACMEOrderPending {
			order.Status = domain.ACMEOrderInvalid
			order.UpdatedAt = now
			if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending); err != nil {
				return err
			}
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.challenge.invalid", "acme_challenge", challenge.ID, now, auditFields(
			"acme_challenge_id", challenge.ID,
			"acme_authorization_id", authorization.ID,
			"acme_order_id", authorization.OrderID,
		))
	})
}

func (s *Service) invalidateACMEOrder(ctx context.Context, actor string, order domain.ACMEOrder) error {
	now := s.clock.Now()
	order.Status = domain.ACMEOrderInvalid
	order.UpdatedAt = now
	return s.repo.WithinTx(ctx, func(repo store.Repository) error {
		if err := repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderReady); err != nil {
			return err
		}
		return s.createAuditEvent(ctx, repo, actor, "acme.order.invalid", "acme_order", order.ID, now, auditFields(
			"acme_account_id", order.AccountID,
			"acme_order_id", order.ID,
		))
	})
}

func acmeExpired(expiresAt time.Time, now time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(now)
}

func (s *Service) promoteACMEAuthorizationIfReady(ctx context.Context, repo store.Repository, authorization domain.ACMEAuthorization, now time.Time) error {
	challenges, err := repo.ListACMEChallengesByAuthorization(ctx, authorization.ID)
	if err != nil {
		return err
	}
	for _, challenge := range challenges {
		if challenge.Status != domain.ACMEChallengeValid {
			return nil
		}
	}
	authorization.Status = domain.ACMEAuthorizationValid
	authorization.UpdatedAt = now
	if err := repo.UpdateACMEAuthorizationIfStatus(ctx, authorization, domain.ACMEAuthorizationPending); err != nil {
		return err
	}
	order, err := repo.GetACMEOrder(ctx, authorization.OrderID)
	if err != nil {
		return err
	}
	return s.promoteACMEOrderIfReady(ctx, repo, order, now)
}

func (s *Service) promoteACMEOrderIfReady(ctx context.Context, repo store.Repository, order domain.ACMEOrder, now time.Time) error {
	if order.Status != domain.ACMEOrderPending {
		return nil
	}
	authorizations, err := repo.ListACMEAuthorizationsByOrder(ctx, order.ID)
	if err != nil {
		return err
	}
	for _, authorization := range authorizations {
		if authorization.Status != domain.ACMEAuthorizationValid {
			return nil
		}
	}
	order.Status = domain.ACMEOrderReady
	order.UpdatedAt = now
	return repo.UpdateACMEOrderIfStatus(ctx, order, domain.ACMEOrderPending)
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

func apiKeyAuditFields(key domain.APIKey) map[string]any {
	fields := auditFields(
		"api_key_id", key.ID,
		"api_key_name", key.Name,
		"api_key_actor", key.Actor,
	)
	fields["api_key_scopes"] = apiKeyScopesToStrings(key.Scopes)
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
	if keyMetadata, ok := ctx.Value(apiKeyAuditMetadataContextKey{}).(APIKeyAuditMetadata); ok {
		if keyMetadata.ID != "" {
			metadata["api_key_id"] = keyMetadata.ID
		}
		if keyMetadata.Name != "" {
			metadata["api_key_name"] = keyMetadata.Name
		}
		if len(keyMetadata.Scopes) > 0 {
			metadata["api_key_scopes"] = apiKeyScopesToStrings(keyMetadata.Scopes)
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
	case errors.Is(err, domain.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, domain.ErrForbidden):
		return "forbidden"
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
	case errors.Is(err, domain.ErrACMEAccountNotFound):
		return "acme_account_not_found"
	case errors.Is(err, domain.ErrACMEOrderNotFound):
		return "acme_order_not_found"
	case errors.Is(err, domain.ErrACMEAuthorizationNotFound):
		return "acme_authorization_not_found"
	case errors.Is(err, domain.ErrACMEChallengeNotFound):
		return "acme_challenge_not_found"
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

func validateAPIKeyScopes(scopes []domain.APIKeyScope) error {
	if len(scopes) == 0 {
		return domain.ErrInvalidRequest
	}
	seen := make(map[domain.APIKeyScope]struct{}, len(scopes))
	for _, scope := range scopes {
		switch scope {
		case domain.APIKeyScopeRead, domain.APIKeyScopeWrite, domain.APIKeyScopeOperator:
		default:
			return domain.ErrInvalidRequest
		}
		if _, ok := seen[scope]; ok {
			return domain.ErrInvalidRequest
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func generateAPIKeyToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func apiKeyScopesToStrings(scopes []domain.APIKeyScope) []string {
	values := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		values = append(values, string(scope))
	}
	return values
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
	if req.Kind == domain.IssuerRootCA && !isBlank(req.ParentIssuerID) {
		return domain.ErrInvalidRequest
	}
	for _, distributionPoint := range req.CRLDistributionPoints {
		if isBlank(distributionPoint) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func validateCreateNotificationEndpointRequest(req CreateNotificationEndpointRequest, productionPolicy bool) error {
	if isBlank(req.Name) || isBlank(req.URL) || isBlank(req.Secret) {
		return domain.ErrInvalidRequest
	}
	parsed, err := url.Parse(req.URL)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return domain.ErrInvalidRequest
	}
	if productionPolicy && (parsed.Scheme != "https" || isWeakWebhookSecret(req.Secret)) {
		return domain.ErrInvalidRequest
	}
	if err := validateACMEHTTP01FetchURL(parsed); err != nil {
		return err
	}
	for _, eventType := range req.EventTypes {
		if isBlank(eventType) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func isWeakWebhookSecret(secret string) bool {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < 32 {
		return true
	}
	if isSingleRepeatedRune(trimmed) {
		return true
	}
	switch strings.ToLower(trimmed) {
	case "change-me", "changeme", "webhook-secret", "secret", "password", "modern-pki":
		return true
	default:
		return false
	}
}

func isSingleRepeatedRune(value string) bool {
	var first rune
	for index, current := range value {
		if index == 0 {
			first = current
			continue
		}
		if current != first {
			return false
		}
	}
	return value != ""
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

func validateCreateACMEAccountRequest(req CreateACMEAccountRequest) error {
	if len(req.Contacts) == 0 || !req.TermsOfServiceAgreed {
		return domain.ErrInvalidRequest
	}
	for _, contact := range req.Contacts {
		if isBlank(contact) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func validateCreateACMEOrderRequest(req CreateACMEOrderRequest, now time.Time) error {
	if isBlank(req.AccountID) || isBlank(req.IdentityID) || isBlank(req.IssuerID) {
		return domain.ErrInvalidRequest
	}
	if len(req.RequestedDNSNames) == 0 && len(req.RequestedIPAddresses) == 0 {
		return domain.ErrInvalidRequest
	}
	if !req.RequestedNotAfter.After(now) {
		return domain.ErrInvalidRequest
	}
	for _, dnsName := range req.RequestedDNSNames {
		if isBlank(dnsName) {
			return domain.ErrInvalidRequest
		}
	}
	for _, ipAddress := range req.RequestedIPAddresses {
		if isBlank(ipAddress) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func validateEnrollmentProfilePolicy(req CreateEnrollmentRequest, profile domain.CertificateProfile, now time.Time) error {
	if profile.ID == "" {
		return nil
	}
	if profile.ValidityPeriodSeconds > 0 {
		maxNotAfter := now.Add(time.Duration(profile.ValidityPeriodSeconds) * time.Second)
		if req.RequestedNotAfter.After(maxNotAfter) {
			return domain.ErrInvalidRequest
		}
	}
	for _, dnsName := range req.RequestedDNSNames {
		if !dnsAllowedByProfile(dnsName, profile.AllowedDNSPatterns) {
			return domain.ErrInvalidRequest
		}
	}
	for _, ipAddress := range req.RequestedIPAddresses {
		if !ipAllowedByProfile(ipAddress, profile.AllowedIPRanges) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func validateEnrollmentIdentityPolicy(req CreateEnrollmentRequest, identity domain.Identity) error {
	if identity.ID == "" {
		return nil
	}
	for _, dnsName := range req.RequestedDNSNames {
		if !valueAllowedByList(dnsName, identity.AllowedDNSNames) {
			return domain.ErrInvalidRequest
		}
	}
	for _, ipAddress := range req.RequestedIPAddresses {
		if !valueAllowedByList(ipAddress, identity.AllowedIPAddresses) {
			return domain.ErrInvalidRequest
		}
	}
	return nil
}

func enrollmentProfilePolicyRequest(enrollment domain.Enrollment) CreateEnrollmentRequest {
	return CreateEnrollmentRequest{
		IdentityID:           enrollment.IdentityID,
		IssuerID:             enrollment.IssuerID,
		CertificateProfileID: enrollment.CertificateProfileID,
		CSRPEM:               enrollment.CSRPEM,
		RequestedSubject:     enrollment.RequestedSubject,
		RequestedDNSNames:    append([]string(nil), enrollment.RequestedDNSNames...),
		RequestedIPAddresses: append([]string(nil), enrollment.RequestedIPAddresses...),
		RequestedNotAfter:    enrollment.RequestedNotAfter,
	}
}

func valueAllowedByList(value string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, candidate := range allowed {
		if strings.TrimSpace(candidate) == value {
			return true
		}
	}
	return false
}

func dnsAllowedByProfile(name string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			return false
		}
		if pattern == name {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(name, suffix) && len(name) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func ipAllowedByProfile(address string, ranges []string) bool {
	if len(ranges) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	for _, rawRange := range ranges {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rawRange))
		if err != nil {
			return false
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
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

func copyStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string(nil), values...)
}
