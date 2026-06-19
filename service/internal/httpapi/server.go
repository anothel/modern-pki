package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/lifecycle"
)

type Server struct {
	service *lifecycle.Service
	mux     *http.ServeMux
	auth    AuthConfig
}

type AuthMode string

const (
	AuthModeDev    AuthMode = "dev"
	AuthModeAPIKey AuthMode = "api_key"
)

type AuthConfig struct {
	Mode AuthMode
}

type requiredScope string

const (
	requiredScopeRead     requiredScope = "read"
	requiredScopeWrite    requiredScope = "write"
	requiredScopeOperator requiredScope = "operator"
)

type actorContextKey struct{}

func New(service *lifecycle.Service) *Server {
	return NewWithAuth(service, AuthConfig{Mode: AuthModeDev})
}

func NewWithAuth(service *lifecycle.Service, auth AuthConfig) *Server {
	if auth.Mode == "" {
		auth.Mode = AuthModeDev
	}
	s := &Server{
		service: service,
		mux:     http.NewServeMux(),
		auth:    auth,
	}
	s.registerRoutes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := lifecycle.WithAuditRequestMetadata(r.Context(), lifecycle.AuditRequestMetadata{
		RequestID: r.Header.Get("X-Request-ID"),
		ClientIP:  requestClientIP(r),
		StartedAt: time.Now(),
	})
	r = r.WithContext(ctx)
	authenticated, err := s.authenticateRequest(r)
	if err != nil {
		r = r.WithContext(context.WithValue(r.Context(), actorContextKey{}, "anonymous"))
		s.writeError(w, r, err)
		return
	}
	r = r.WithContext(authenticated)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("POST /identities", s.createIdentity)
	s.mux.HandleFunc("GET /identities", s.listIdentities)
	s.mux.HandleFunc("GET /identities/{id}", s.getIdentity)

	s.mux.HandleFunc("POST /issuers", s.createIssuer)
	s.mux.HandleFunc("GET /issuers/{id}/chain", s.getIssuerChain)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders", s.createOCSPResponder)
	s.mux.HandleFunc("GET /issuers/{id}/ocsp-responders", s.listOCSPResponders)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders/rotate", s.rotateOCSPResponder)
	s.mux.HandleFunc("POST /issuers/{id}/ocsp-responders/{responderID}/disable", s.disableOCSPResponder)

	s.mux.HandleFunc("POST /notification-endpoints", s.createNotificationEndpoint)
	s.mux.HandleFunc("GET /notification-endpoints", s.listNotificationEndpoints)
	s.mux.HandleFunc("POST /notification-endpoints/{id}/disable", s.disableNotificationEndpoint)

	s.mux.HandleFunc("GET /outbox/messages", s.listOutboxMessages)
	s.mux.HandleFunc("POST /outbox/messages/{id}/retry", s.retryOutboxMessage)

	s.mux.HandleFunc("POST /api-keys", s.createAPIKey)
	s.mux.HandleFunc("GET /api-keys", s.listAPIKeys)
	s.mux.HandleFunc("POST /api-keys/{id}/disable", s.disableAPIKey)

	s.mux.HandleFunc("POST /certificate-profiles", s.createCertificateProfile)
	s.mux.HandleFunc("GET /certificate-profiles", s.listCertificateProfiles)
	s.mux.HandleFunc("GET /certificate-profiles/{id}", s.getCertificateProfile)

	s.mux.HandleFunc("POST /enrollments", s.createEnrollment)
	s.mux.HandleFunc("GET /enrollments", s.listEnrollments)
	s.mux.HandleFunc("GET /enrollments/{id}", s.getEnrollment)
	s.mux.HandleFunc("POST /enrollments/{id}/approve", s.approveEnrollment)
	s.mux.HandleFunc("POST /enrollments/{id}/reject", s.rejectEnrollment)

	s.mux.HandleFunc("POST /certificates", s.issueCertificate)
	s.mux.HandleFunc("GET /certificates", s.listCertificates)
	s.mux.HandleFunc("POST /certificates/expiration-scan", s.scanCertificateExpirations)
	s.mux.HandleFunc("GET /certificates/{id}", s.getCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/revoke", s.revokeCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/suspend", s.suspendCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/resume", s.resumeCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/renew", s.renewCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/reissue", s.reissueCertificate)

	s.mux.HandleFunc("POST /crls", s.publishCRL)
	s.mux.HandleFunc("GET /crls/{id}", s.getCRLPublication)
	s.mux.HandleFunc("GET /issuers/{id}/crl", s.getLatestIssuerCRL)

	s.mux.HandleFunc("POST /ocsp", s.respondOCSP)

	s.mux.HandleFunc("GET /audit-events", s.listAuditEvents)
	s.mux.HandleFunc("GET /trust/anchors", s.listTrustAnchors)
}

func (s *Server) createIdentity(w http.ResponseWriter, r *http.Request) {
	var req createIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	identity, err := s.service.CreateIdentity(r.Context(), requestActor(r), lifecycle.CreateIdentityRequest{
		Type:       req.Type,
		Name:       req.Name,
		ExternalID: req.ExternalID,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIdentityResponse(identity))
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) {
	identities, err := s.service.ListIdentities(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponses(identities))
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request) {
	identity, err := s.service.GetIdentity(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponse(identity))
}

func (s *Server) createIssuer(w http.ResponseWriter, r *http.Request) {
	var req createIssuerRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	issuer, err := s.service.CreateIssuer(r.Context(), requestActor(r), lifecycle.CreateIssuerRequest{
		Name:                  req.Name,
		Kind:                  req.Kind,
		ParentIssuerID:        req.ParentIssuerID,
		CertificatePEM:        req.CertificatePEM,
		KeyRef:                req.KeyRef,
		AIAURL:                req.AIAURL,
		CRLDistributionPoints: req.CRLDistributionPoints,
		TrustAnchor:           req.TrustAnchor,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIssuerResponse(issuer))
}

func (s *Server) getIssuerChain(w http.ResponseWriter, r *http.Request) {
	chain, err := s.service.GetIssuerChain(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIssuerResponses(chain))
}

func (s *Server) createOCSPResponder(w http.ResponseWriter, r *http.Request) {
	var req createOCSPResponderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	responder, err := s.service.CreateOCSPResponder(r.Context(), requestActor(r), lifecycle.CreateOCSPResponderRequest{
		IssuerID:       r.PathValue("id"),
		Name:           req.Name,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOCSPResponderResponse(responder))
}

func (s *Server) listOCSPResponders(w http.ResponseWriter, r *http.Request) {
	responders, err := s.service.ListOCSPRespondersByIssuer(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOCSPResponderResponses(responders))
}

func (s *Server) disableOCSPResponder(w http.ResponseWriter, r *http.Request) {
	responder, err := s.service.DisableOCSPResponder(r.Context(), requestActor(r), r.PathValue("id"), r.PathValue("responderID"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOCSPResponderResponse(responder))
}

func (s *Server) rotateOCSPResponder(w http.ResponseWriter, r *http.Request) {
	var req createOCSPResponderRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	responder, err := s.service.RotateOCSPResponder(r.Context(), requestActor(r), lifecycle.RotateOCSPResponderRequest{
		IssuerID:       r.PathValue("id"),
		Name:           req.Name,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOCSPResponderResponse(responder))
}

func (s *Server) createNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	var req createNotificationEndpointRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	endpoint, err := s.service.CreateNotificationEndpoint(r.Context(), requestActor(r), lifecycle.CreateNotificationEndpointRequest{
		Name:       req.Name,
		URL:        req.URL,
		Secret:     req.Secret,
		EventTypes: req.EventTypes,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toNotificationEndpointResponse(endpoint))
}

func (s *Server) listNotificationEndpoints(w http.ResponseWriter, r *http.Request) {
	endpoints, err := s.service.ListNotificationEndpoints(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNotificationEndpointResponses(endpoints))
}

func (s *Server) disableNotificationEndpoint(w http.ResponseWriter, r *http.Request) {
	endpoint, err := s.service.DisableNotificationEndpoint(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toNotificationEndpointResponse(endpoint))
}

func (s *Server) listOutboxMessages(w http.ResponseWriter, r *http.Request) {
	messages, err := s.service.ListOutboxMessages(r.Context(), domain.OutboxMessageStatus(r.URL.Query().Get("status")))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOutboxMessageResponses(messages))
}

func (s *Server) retryOutboxMessage(w http.ResponseWriter, r *http.Request) {
	message, err := s.service.RetryOutboxMessage(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toOutboxMessageResponse(message))
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	result, err := s.service.CreateAPIKey(r.Context(), requestActor(r), lifecycle.CreateAPIKeyRequest{
		Name:   req.Name,
		Actor:  req.Actor,
		Scopes: req.Scopes,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toAPIKeyResponseWithToken(result.Key, result.Token))
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.service.ListAPIKeys(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPIKeyResponses(keys))
}

func (s *Server) disableAPIKey(w http.ResponseWriter, r *http.Request) {
	key, err := s.service.DisableAPIKey(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAPIKeyResponse(key))
}

func (s *Server) createCertificateProfile(w http.ResponseWriter, r *http.Request) {
	var req createCertificateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	profile, err := s.service.CreateCertificateProfile(r.Context(), requestActor(r), lifecycle.CreateCertificateProfileRequest{
		Name:                   req.Name,
		Description:            req.Description,
		IssuerID:               req.IssuerID,
		ValidityPeriodSeconds:  req.ValidityPeriodSeconds,
		SubjectTemplate:        req.SubjectTemplate,
		AllowedDNSPatterns:     req.AllowedDNSPatterns,
		AllowedIPRanges:        req.AllowedIPRanges,
		KeyUsage:               req.KeyUsage,
		ExtendedKeyUsage:       req.ExtendedKeyUsage,
		BasicConstraints:       req.BasicConstraints,
		SubjectKeyIdentifier:   req.SubjectKeyIdentifier,
		AuthorityKeyIdentifier: req.AuthorityKeyIdentifier,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateProfileResponse(profile))
}

func (s *Server) listCertificateProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.service.ListCertificateProfiles(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponses(profiles))
}

func (s *Server) getCertificateProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := s.service.GetCertificateProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponse(profile))
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req createEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.CreateEnrollment(r.Context(), requestActor(r), lifecycle.CreateEnrollmentRequest{
		IdentityID:           req.IdentityID,
		IssuerID:             req.IssuerID,
		CertificateProfileID: req.CertificateProfileID,
		CSRPEM:               req.CSRPEM,
		RequestedSubject:     req.RequestedSubject,
		RequestedDNSNames:    req.RequestedDNSNames,
		RequestedIPAddresses: req.RequestedIPAddresses,
		RequestedNotAfter:    req.RequestedNotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	enrollments, err := s.service.ListEnrollments(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponses(enrollments))
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.GetEnrollment(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.ApproveEnrollment(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) rejectEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.RejectEnrollment(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	certificate, err := s.service.IssueCertificate(r.Context(), requestActor(r), req.EnrollmentID)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateResponse(certificate))
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	certificates, err := s.service.ListCertificates(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponses(certificates))
}

func (s *Server) scanCertificateExpirations(w http.ResponseWriter, r *http.Request) {
	var req scanCertificateExpirationsRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	result, err := s.service.ScanCertificateExpirations(r.Context(), requestActor(r), lifecycle.ScanCertificateExpirationsRequest{
		WarningWindow: time.Duration(req.WarningWindowSeconds) * time.Second,
		Limit:         req.Limit,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateExpirationScanResponse(result))
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var req revokeCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	var certificate domain.Certificate
	var err error
	if req.Force {
		certificate, err = s.service.ForceRevokeCertificate(r.Context(), requestActor(r), r.PathValue("id"), req.Reason)
	} else {
		certificate, err = s.service.RevokeCertificate(r.Context(), requestActor(r), r.PathValue("id"), req.Reason)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) suspendCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.SuspendCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) resumeCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.ResumeCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) renewCertificate(w http.ResponseWriter, r *http.Request) {
	var req renewCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.RenewCertificate(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.RenewCertificateRequest{
		CSRPEM:            req.CSRPEM,
		RequestedNotAfter: req.RequestedNotAfter,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) reissueCertificate(w http.ResponseWriter, r *http.Request) {
	var req reissueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	enrollment, err := s.service.ReissueCertificate(r.Context(), requestActor(r), r.PathValue("id"), lifecycle.ReissueCertificateRequest{
		CSRPEM: req.CSRPEM,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) publishCRL(w http.ResponseWriter, r *http.Request) {
	var req publishCRLRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, r, err)
		return
	}

	publication, err := s.service.PublishCRL(r.Context(), requestActor(r), lifecycle.PublishCRLRequest{
		IssuerID:          req.IssuerID,
		DistributionPoint: req.DistributionPoint,
		NextUpdate:        req.NextUpdate,
	})
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCRLPublicationResponse(publication))
}

func (s *Server) getCRLPublication(w http.ResponseWriter, r *http.Request) {
	publication, err := s.service.GetCRLPublication(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toCRLPublicationResponse(publication))
}

func (s *Server) getLatestIssuerCRL(w http.ResponseWriter, r *http.Request) {
	distributionPoint := r.URL.Query().Get("distribution_point")
	var publication domain.CRLPublication
	var err error
	if distributionPoint == "" {
		publication, err = s.service.GetLatestCRLPublication(r.Context(), r.PathValue("id"))
	} else {
		publication, err = s.service.GetLatestCRLPublicationForDistributionPoint(r.Context(), r.PathValue("id"), distributionPoint)
	}
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(publication.CRLPEM))
}

func (s *Server) respondOCSP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		s.writeError(w, r, domain.ErrUnsupportedMediaType)
		return
	}
	requestDER, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, domain.ErrInvalidRequest)
		return
	}
	response, err := s.service.RespondOCSP(r.Context(), requestActor(r), requestDER)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.ResponseDER)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.service.ListAuditEvents(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuditEventResponses(events))
}

func (s *Server) listTrustAnchors(w http.ResponseWriter, r *http.Request) {
	anchors, err := s.service.ListTrustAnchors(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toIssuerResponses(anchors))
}

func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return domain.ErrInvalidRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.ErrInvalidRequest
	}
	return nil
}

func requestActor(r *http.Request) string {
	if actor, ok := r.Context().Value(actorContextKey{}).(string); ok && actor != "" {
		return actor
	}
	actor := r.Header.Get("X-Actor")
	if actor == "" {
		return "anonymous"
	}
	return actor
}

func (s *Server) authenticateRequest(r *http.Request) (context.Context, error) {
	switch s.auth.Mode {
	case AuthModeDev, "":
		return context.WithValue(r.Context(), actorContextKey{}, requestActor(r)), nil
	case AuthModeAPIKey:
		if isPublicEndpoint(r.Method, r.URL.Path) {
			return context.WithValue(r.Context(), actorContextKey{}, "public"), nil
		}
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			return r.Context(), domain.ErrUnauthorized
		}
		key, err := s.service.AuthenticateAPIKey(r.Context(), token)
		if err != nil {
			return r.Context(), err
		}
		if !apiKeyAllowsScope(key, requiredScopeForRequest(r.Method, r.URL.Path)) {
			ctx := context.WithValue(r.Context(), actorContextKey{}, key.Actor)
			ctx = lifecycle.WithAPIKeyAuditMetadata(ctx, lifecycle.APIKeyAuditMetadata{
				ID:     key.ID,
				Name:   key.Name,
				Scopes: key.Scopes,
			})
			return ctx, domain.ErrForbidden
		}
		ctx := context.WithValue(r.Context(), actorContextKey{}, key.Actor)
		return lifecycle.WithAPIKeyAuditMetadata(ctx, lifecycle.APIKeyAuditMetadata{
			ID:     key.ID,
			Name:   key.Name,
			Scopes: key.Scopes,
		}), nil
	default:
		return r.Context(), domain.ErrUnauthorized
	}
}

func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	return token, token != ""
}

func isPublicEndpoint(method string, path string) bool {
	if method == http.MethodPost && path == "/ocsp" {
		return true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/crls/") && len(strings.TrimPrefix(path, "/crls/")) > 0 {
		return true
	}
	if method != http.MethodGet || !strings.HasPrefix(path, "/issuers/") || !strings.HasSuffix(path, "/crl") {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	return len(parts) == 3 && parts[0] == "issuers" && parts[1] != "" && parts[2] == "crl"
}

func requiredScopeForRequest(method string, path string) requiredScope {
	if strings.HasPrefix(path, "/api-keys") || strings.HasPrefix(path, "/outbox/") || path == "/audit-events" {
		return requiredScopeOperator
	}
	if method == http.MethodPost && path == "/certificates/expiration-scan" {
		return requiredScopeOperator
	}
	if method == http.MethodGet {
		return requiredScopeRead
	}
	return requiredScopeWrite
}

func apiKeyAllowsScope(key domain.APIKey, required requiredScope) bool {
	for _, scope := range key.Scopes {
		if scope == domain.APIKeyScopeOperator {
			return true
		}
		if required == requiredScopeRead && scope == domain.APIKeyScopeWrite {
			return true
		}
		if string(scope) == string(required) {
			return true
		}
	}
	return false
}

func requestClientIP(r *http.Request) string {
	forwardedFor := r.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
		clientIP := strings.TrimSpace(strings.Split(forwardedFor, ",")[0])
		if clientIP != "" {
			return clientIP
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	status := statusForError(err)
	_ = s.service.RecordAPIFailure(r.Context(), requestActor(r), lifecycle.APIFailureAuditRequest{
		Method:     r.Method,
		Path:       r.URL.Path,
		StatusCode: status,
		Err:        err,
	})
	writeJSON(w, status, errorResponse{Error: publicErrorMessage(err)})
}

func publicErrorMessage(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest):
		return domain.ErrInvalidRequest.Error()
	case errors.Is(err, domain.ErrUnsupportedMediaType):
		return domain.ErrUnsupportedMediaType.Error()
	case errors.Is(err, domain.ErrUnauthorized):
		return domain.ErrUnauthorized.Error()
	case errors.Is(err, domain.ErrForbidden):
		return domain.ErrForbidden.Error()
	case errors.Is(err, domain.ErrInvalidTransition):
		return domain.ErrInvalidTransition.Error()
	case errors.Is(err, domain.ErrIdentityNotFound):
		return domain.ErrIdentityNotFound.Error()
	case errors.Is(err, domain.ErrIssuerNotFound):
		return domain.ErrIssuerNotFound.Error()
	case errors.Is(err, domain.ErrOCSPResponderNotFound):
		return domain.ErrOCSPResponderNotFound.Error()
	case errors.Is(err, domain.ErrNotificationEndpointNotFound):
		return domain.ErrNotificationEndpointNotFound.Error()
	case errors.Is(err, domain.ErrCertificateProfileNotFound):
		return domain.ErrCertificateProfileNotFound.Error()
	case errors.Is(err, domain.ErrEnrollmentNotFound):
		return domain.ErrEnrollmentNotFound.Error()
	case errors.Is(err, domain.ErrCertificateNotFound):
		return domain.ErrCertificateNotFound.Error()
	case errors.Is(err, domain.ErrCRLPublicationNotFound):
		return domain.ErrCRLPublicationNotFound.Error()
	case errors.Is(err, domain.ErrOutboxMessageNotFound):
		return domain.ErrOutboxMessageNotFound.Error()
	case errors.Is(err, domain.ErrAPIKeyNotFound):
		return domain.ErrAPIKeyNotFound.Error()
	case errors.Is(err, domain.ErrCSRParseFailed):
		return domain.ErrCSRParseFailed.Error()
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return domain.ErrCertificateIssuanceFailed.Error()
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return domain.ErrCRLGenerationFailed.Error()
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return domain.ErrOCSPDecodeFailed.Error()
	case errors.Is(err, domain.ErrOCSPResponderValidationFailed):
		return domain.ErrOCSPResponderValidationFailed.Error()
	case errors.Is(err, domain.ErrOCSPResponseFailed):
		return domain.ErrOCSPResponseFailed.Error()
	case errors.Is(err, domain.ErrStorageFailure):
		return domain.ErrStorageFailure.Error()
	default:
		return "internal server error"
	}
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrUnsupportedMediaType):
		return http.StatusUnsupportedMediaType
	case errors.Is(err, domain.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrInvalidTransition):
		return http.StatusConflict
	case errors.Is(err, domain.ErrIdentityNotFound),
		errors.Is(err, domain.ErrIssuerNotFound),
		errors.Is(err, domain.ErrOCSPResponderNotFound),
		errors.Is(err, domain.ErrNotificationEndpointNotFound),
		errors.Is(err, domain.ErrCertificateProfileNotFound),
		errors.Is(err, domain.ErrEnrollmentNotFound),
		errors.Is(err, domain.ErrCertificateNotFound),
		errors.Is(err, domain.ErrCRLPublicationNotFound),
		errors.Is(err, domain.ErrOutboxMessageNotFound),
		errors.Is(err, domain.ErrAPIKeyNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrCSRParseFailed):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrOCSPResponderValidationFailed):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrOCSPResponseFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrStorageFailure):
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

type createIdentityRequest struct {
	Type       domain.IdentityType `json:"type"`
	Name       string              `json:"name"`
	ExternalID string              `json:"external_id"`
}

type createIssuerRequest struct {
	Name                  string            `json:"name"`
	Kind                  domain.IssuerKind `json:"kind"`
	ParentIssuerID        string            `json:"parent_issuer_id"`
	CertificatePEM        string            `json:"certificate_pem"`
	KeyRef                string            `json:"key_ref"`
	AIAURL                string            `json:"aia_url"`
	CRLDistributionPoints []string          `json:"crl_distribution_points"`
	TrustAnchor           bool              `json:"trust_anchor"`
}

type createOCSPResponderRequest struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	KeyRef         string `json:"key_ref"`
}

type createNotificationEndpointRequest struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Secret     string   `json:"secret"`
	EventTypes []string `json:"event_types"`
}

type createCertificateProfileRequest struct {
	Name                   string                           `json:"name"`
	Description            string                           `json:"description"`
	IssuerID               string                           `json:"issuer_id"`
	ValidityPeriodSeconds  int64                            `json:"validity_period_seconds"`
	SubjectTemplate        string                           `json:"subject_template"`
	AllowedDNSPatterns     []string                         `json:"allowed_dns_patterns"`
	AllowedIPRanges        []string                         `json:"allowed_ip_ranges"`
	KeyUsage               domain.StringListExtensionPolicy `json:"key_usage"`
	ExtendedKeyUsage       domain.StringListExtensionPolicy `json:"extended_key_usage"`
	BasicConstraints       domain.BasicConstraintsPolicy    `json:"basic_constraints"`
	SubjectKeyIdentifier   bool                             `json:"subject_key_identifier"`
	AuthorityKeyIdentifier bool                             `json:"authority_key_identifier"`
}

type createEnrollmentRequest struct {
	IdentityID           string    `json:"identity_id"`
	IssuerID             string    `json:"issuer_id"`
	CertificateProfileID string    `json:"profile_id"`
	CSRPEM               string    `json:"csr_pem"`
	RequestedSubject     string    `json:"requested_subject"`
	RequestedDNSNames    []string  `json:"requested_dns_names"`
	RequestedIPAddresses []string  `json:"requested_ip_addresses"`
	RequestedNotAfter    time.Time `json:"requested_not_after"`
}

type issueCertificateRequest struct {
	EnrollmentID string `json:"enrollment_id"`
}

type revokeCertificateRequest struct {
	Reason domain.RevocationReason `json:"reason"`
	Force  bool                    `json:"force,omitempty"`
}

type renewCertificateRequest struct {
	CSRPEM            string    `json:"csr_pem"`
	RequestedNotAfter time.Time `json:"requested_not_after"`
}

type reissueCertificateRequest struct {
	CSRPEM string `json:"csr_pem"`
}

type scanCertificateExpirationsRequest struct {
	WarningWindowSeconds int64 `json:"warning_window_seconds"`
	Limit                int   `json:"limit"`
}

type createAPIKeyRequest struct {
	Name   string               `json:"name"`
	Actor  string               `json:"actor"`
	Scopes []domain.APIKeyScope `json:"scopes"`
}

type publishCRLRequest struct {
	IssuerID          string    `json:"issuer_id"`
	DistributionPoint string    `json:"distribution_point"`
	NextUpdate        time.Time `json:"next_update"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type identityResponse struct {
	ID         string                `json:"id"`
	Type       domain.IdentityType   `json:"type"`
	Name       string                `json:"name"`
	ExternalID string                `json:"external_id"`
	Status     domain.IdentityStatus `json:"status"`
	CreatedAt  time.Time             `json:"created_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

type issuerResponse struct {
	ID                    string              `json:"id"`
	Name                  string              `json:"name"`
	Kind                  domain.IssuerKind   `json:"kind"`
	Status                domain.IssuerStatus `json:"status"`
	ParentIssuerID        string              `json:"parent_issuer_id"`
	CertificatePEM        string              `json:"certificate_pem"`
	KeyRef                string              `json:"key_ref"`
	AIAURL                string              `json:"aia_url"`
	CRLDistributionPoints []string            `json:"crl_distribution_points"`
	TrustAnchor           bool                `json:"trust_anchor"`
	CreatedAt             time.Time           `json:"created_at"`
	UpdatedAt             time.Time           `json:"updated_at"`
}

type ocspResponderResponse struct {
	ID             string                     `json:"id"`
	IssuerID       string                     `json:"issuer_id"`
	Name           string                     `json:"name"`
	Status         domain.OCSPResponderStatus `json:"status"`
	CertificatePEM string                     `json:"certificate_pem"`
	KeyRef         string                     `json:"key_ref"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

type notificationEndpointResponse struct {
	ID         string                            `json:"id"`
	Name       string                            `json:"name"`
	Type       domain.NotificationEndpointType   `json:"type"`
	Status     domain.NotificationEndpointStatus `json:"status"`
	URL        string                            `json:"url"`
	EventTypes []string                          `json:"event_types"`
	CreatedAt  time.Time                         `json:"created_at"`
	UpdatedAt  time.Time                         `json:"updated_at"`
}

type outboxMessageResponse struct {
	ID           string                     `json:"id"`
	Type         string                     `json:"type"`
	PayloadJSON  string                     `json:"payload_json"`
	Status       domain.OutboxMessageStatus `json:"status"`
	AvailableAt  time.Time                  `json:"available_at"`
	AttemptCount int                        `json:"attempt_count"`
	MaxAttempts  int                        `json:"max_attempts"`
	LastError    string                     `json:"last_error"`
	CreatedAt    time.Time                  `json:"created_at"`
	UpdatedAt    time.Time                  `json:"updated_at"`
}

type apiKeyResponse struct {
	ID        string               `json:"id"`
	Name      string               `json:"name"`
	Actor     string               `json:"actor"`
	Status    domain.APIKeyStatus  `json:"status"`
	Scopes    []domain.APIKeyScope `json:"scopes"`
	Token     string               `json:"token,omitempty"`
	TokenHash string               `json:"token_hash,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type certificateProfileResponse struct {
	ID                     string                           `json:"id"`
	Name                   string                           `json:"name"`
	Description            string                           `json:"description"`
	IssuerID               string                           `json:"issuer_id"`
	ValidityPeriodSeconds  int64                            `json:"validity_period_seconds"`
	SubjectTemplate        string                           `json:"subject_template"`
	AllowedDNSPatterns     []string                         `json:"allowed_dns_patterns"`
	AllowedIPRanges        []string                         `json:"allowed_ip_ranges"`
	KeyUsage               domain.StringListExtensionPolicy `json:"key_usage"`
	ExtendedKeyUsage       domain.StringListExtensionPolicy `json:"extended_key_usage"`
	BasicConstraints       domain.BasicConstraintsPolicy    `json:"basic_constraints"`
	SubjectKeyIdentifier   bool                             `json:"subject_key_identifier"`
	AuthorityKeyIdentifier bool                             `json:"authority_key_identifier"`
	CreatedAt              time.Time                        `json:"created_at"`
	UpdatedAt              time.Time                        `json:"updated_at"`
}

type enrollmentResponse struct {
	ID                   string                  `json:"id"`
	IdentityID           string                  `json:"identity_id"`
	IssuerID             string                  `json:"issuer_id"`
	CertificateProfileID string                  `json:"profile_id"`
	CSRPEM               string                  `json:"csr_pem"`
	Status               domain.EnrollmentStatus `json:"status"`
	RequestedSubject     string                  `json:"requested_subject"`
	RequestedDNSNames    []string                `json:"requested_dns_names"`
	RequestedIPAddresses []string                `json:"requested_ip_addresses"`
	CSRDNSNames          []string                `json:"csr_dns_names"`
	CSRIPAddresses       []string                `json:"csr_ip_addresses"`
	RequestedNotAfter    time.Time               `json:"requested_not_after"`
	ApprovedBy           string                  `json:"approved_by"`
	ApprovedAt           time.Time               `json:"approved_at"`
	CreatedAt            time.Time               `json:"created_at"`
	UpdatedAt            time.Time               `json:"updated_at"`
}

type certificateResponse struct {
	ID                   string                   `json:"id"`
	IdentityID           string                   `json:"identity_id"`
	IssuerID             string                   `json:"issuer_id"`
	EnrollmentID         string                   `json:"enrollment_id"`
	CertificateProfileID string                   `json:"profile_id"`
	SerialNumber         string                   `json:"serial_number"`
	Subject              string                   `json:"subject"`
	DNSNames             []string                 `json:"dns_names"`
	IPAddresses          []string                 `json:"ip_addresses"`
	NotBefore            time.Time                `json:"not_before"`
	NotAfter             time.Time                `json:"not_after"`
	Status               domain.CertificateStatus `json:"status"`
	CertificatePEM       string                   `json:"certificate_pem"`
	RenewalNotifiedAt    time.Time                `json:"renewal_notified_at"`
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
}

type certificateExpirationScanResponse struct {
	Expired            []certificateResponse `json:"expired"`
	ExpirationWarnings []certificateResponse `json:"expiration_warnings"`
}

type crlPublicationResponse struct {
	ID                string                      `json:"id"`
	IssuerID          string                      `json:"issuer_id"`
	DistributionPoint string                      `json:"distribution_point"`
	CRLNumber         int64                       `json:"crl_number"`
	ThisUpdate        time.Time                   `json:"this_update"`
	NextUpdate        time.Time                   `json:"next_update"`
	Status            domain.CRLPublicationStatus `json:"status"`
	CRLPEM            string                      `json:"crl_pem"`
	CreatedAt         time.Time                   `json:"created_at"`
	UpdatedAt         time.Time                   `json:"updated_at"`
}

type auditEventResponse struct {
	ID           string    `json:"id"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	MetadataJSON string    `json:"metadata_json"`
	CreatedAt    time.Time `json:"created_at"`
}

func toIdentityResponse(identity domain.Identity) identityResponse {
	return identityResponse{
		ID:         identity.ID,
		Type:       identity.Type,
		Name:       identity.Name,
		ExternalID: identity.ExternalID,
		Status:     identity.Status,
		CreatedAt:  identity.CreatedAt,
		UpdatedAt:  identity.UpdatedAt,
	}
}

func toIdentityResponses(identities []domain.Identity) []identityResponse {
	responses := make([]identityResponse, 0, len(identities))
	for _, identity := range identities {
		responses = append(responses, toIdentityResponse(identity))
	}
	return responses
}

func toIssuerResponse(issuer domain.Issuer) issuerResponse {
	return issuerResponse{
		ID:                    issuer.ID,
		Name:                  issuer.Name,
		Kind:                  issuer.Kind,
		Status:                issuer.Status,
		ParentIssuerID:        issuer.ParentIssuerID,
		CertificatePEM:        issuer.CertificatePEM,
		KeyRef:                issuer.KeyRef,
		AIAURL:                issuer.AIAURL,
		CRLDistributionPoints: issuer.CRLDistributionPoints,
		TrustAnchor:           issuer.TrustAnchor,
		CreatedAt:             issuer.CreatedAt,
		UpdatedAt:             issuer.UpdatedAt,
	}
}

func toIssuerResponses(issuers []domain.Issuer) []issuerResponse {
	responses := make([]issuerResponse, 0, len(issuers))
	for _, issuer := range issuers {
		responses = append(responses, toIssuerResponse(issuer))
	}
	return responses
}

func toOCSPResponderResponse(responder domain.OCSPResponder) ocspResponderResponse {
	return ocspResponderResponse{
		ID:             responder.ID,
		IssuerID:       responder.IssuerID,
		Name:           responder.Name,
		Status:         responder.Status,
		CertificatePEM: responder.CertificatePEM,
		KeyRef:         responder.KeyRef,
		CreatedAt:      responder.CreatedAt,
		UpdatedAt:      responder.UpdatedAt,
	}
}

func toOCSPResponderResponses(responders []domain.OCSPResponder) []ocspResponderResponse {
	responses := make([]ocspResponderResponse, 0, len(responders))
	for _, responder := range responders {
		responses = append(responses, toOCSPResponderResponse(responder))
	}
	return responses
}

func toNotificationEndpointResponse(endpoint domain.NotificationEndpoint) notificationEndpointResponse {
	return notificationEndpointResponse{
		ID:         endpoint.ID,
		Name:       endpoint.Name,
		Type:       endpoint.Type,
		Status:     endpoint.Status,
		URL:        endpoint.URL,
		EventTypes: endpoint.EventTypes,
		CreatedAt:  endpoint.CreatedAt,
		UpdatedAt:  endpoint.UpdatedAt,
	}
}

func toNotificationEndpointResponses(endpoints []domain.NotificationEndpoint) []notificationEndpointResponse {
	responses := make([]notificationEndpointResponse, 0, len(endpoints))
	for _, endpoint := range endpoints {
		responses = append(responses, toNotificationEndpointResponse(endpoint))
	}
	return responses
}

func toOutboxMessageResponse(message domain.OutboxMessage) outboxMessageResponse {
	return outboxMessageResponse{
		ID:           message.ID,
		Type:         message.Type,
		PayloadJSON:  message.PayloadJSON,
		Status:       message.Status,
		AvailableAt:  message.AvailableAt,
		AttemptCount: message.AttemptCount,
		MaxAttempts:  message.MaxAttempts,
		LastError:    message.LastError,
		CreatedAt:    message.CreatedAt,
		UpdatedAt:    message.UpdatedAt,
	}
}

func toOutboxMessageResponses(messages []domain.OutboxMessage) []outboxMessageResponse {
	responses := make([]outboxMessageResponse, 0, len(messages))
	for _, message := range messages {
		responses = append(responses, toOutboxMessageResponse(message))
	}
	return responses
}

func toAPIKeyResponse(key domain.APIKey) apiKeyResponse {
	return apiKeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Actor:     key.Actor,
		Status:    key.Status,
		Scopes:    key.Scopes,
		CreatedAt: key.CreatedAt,
		UpdatedAt: key.UpdatedAt,
	}
}

func toAPIKeyResponseWithToken(key domain.APIKey, token string) apiKeyResponse {
	response := toAPIKeyResponse(key)
	response.Token = token
	return response
}

func toAPIKeyResponses(keys []domain.APIKey) []apiKeyResponse {
	responses := make([]apiKeyResponse, 0, len(keys))
	for _, key := range keys {
		responses = append(responses, toAPIKeyResponse(key))
	}
	return responses
}

func toCertificateProfileResponse(profile domain.CertificateProfile) certificateProfileResponse {
	return certificateProfileResponse{
		ID:                     profile.ID,
		Name:                   profile.Name,
		Description:            profile.Description,
		IssuerID:               profile.IssuerID,
		ValidityPeriodSeconds:  profile.ValidityPeriodSeconds,
		SubjectTemplate:        profile.SubjectTemplate,
		AllowedDNSPatterns:     profile.AllowedDNSPatterns,
		AllowedIPRanges:        profile.AllowedIPRanges,
		KeyUsage:               profile.KeyUsage,
		ExtendedKeyUsage:       profile.ExtendedKeyUsage,
		BasicConstraints:       profile.BasicConstraints,
		SubjectKeyIdentifier:   profile.SubjectKeyIdentifier,
		AuthorityKeyIdentifier: profile.AuthorityKeyIdentifier,
		CreatedAt:              profile.CreatedAt,
		UpdatedAt:              profile.UpdatedAt,
	}
}

func toCertificateProfileResponses(profiles []domain.CertificateProfile) []certificateProfileResponse {
	responses := make([]certificateProfileResponse, 0, len(profiles))
	for _, profile := range profiles {
		responses = append(responses, toCertificateProfileResponse(profile))
	}
	return responses
}

func toEnrollmentResponse(enrollment domain.Enrollment) enrollmentResponse {
	return enrollmentResponse{
		ID:                   enrollment.ID,
		IdentityID:           enrollment.IdentityID,
		IssuerID:             enrollment.IssuerID,
		CertificateProfileID: enrollment.CertificateProfileID,
		CSRPEM:               enrollment.CSRPEM,
		Status:               enrollment.Status,
		RequestedSubject:     enrollment.RequestedSubject,
		RequestedDNSNames:    enrollment.RequestedDNSNames,
		RequestedIPAddresses: enrollment.RequestedIPAddresses,
		CSRDNSNames:          enrollment.CSRDNSNames,
		CSRIPAddresses:       enrollment.CSRIPAddresses,
		RequestedNotAfter:    enrollment.RequestedNotAfter,
		ApprovedBy:           enrollment.ApprovedBy,
		ApprovedAt:           enrollment.ApprovedAt,
		CreatedAt:            enrollment.CreatedAt,
		UpdatedAt:            enrollment.UpdatedAt,
	}
}

func toEnrollmentResponses(enrollments []domain.Enrollment) []enrollmentResponse {
	responses := make([]enrollmentResponse, 0, len(enrollments))
	for _, enrollment := range enrollments {
		responses = append(responses, toEnrollmentResponse(enrollment))
	}
	return responses
}

func toCertificateResponse(certificate domain.Certificate) certificateResponse {
	return certificateResponse{
		ID:                   certificate.ID,
		IdentityID:           certificate.IdentityID,
		IssuerID:             certificate.IssuerID,
		EnrollmentID:         certificate.EnrollmentID,
		CertificateProfileID: certificate.CertificateProfileID,
		SerialNumber:         certificate.SerialNumber,
		Subject:              certificate.Subject,
		DNSNames:             certificate.DNSNames,
		IPAddresses:          certificate.IPAddresses,
		NotBefore:            certificate.NotBefore,
		NotAfter:             certificate.NotAfter,
		Status:               certificate.Status,
		CertificatePEM:       certificate.CertificatePEM,
		RenewalNotifiedAt:    certificate.RenewalNotifiedAt,
		CreatedAt:            certificate.CreatedAt,
		UpdatedAt:            certificate.UpdatedAt,
	}
}

func toCertificateResponses(certificates []domain.Certificate) []certificateResponse {
	responses := make([]certificateResponse, 0, len(certificates))
	for _, certificate := range certificates {
		responses = append(responses, toCertificateResponse(certificate))
	}
	return responses
}

func toCertificateExpirationScanResponse(result lifecycle.CertificateExpirationScanResult) certificateExpirationScanResponse {
	return certificateExpirationScanResponse{
		Expired:            toCertificateResponses(result.Expired),
		ExpirationWarnings: toCertificateResponses(result.ExpirationWarnings),
	}
}

func toCRLPublicationResponse(publication domain.CRLPublication) crlPublicationResponse {
	return crlPublicationResponse{
		ID:                publication.ID,
		IssuerID:          publication.IssuerID,
		DistributionPoint: publication.DistributionPoint,
		CRLNumber:         publication.CRLNumber,
		ThisUpdate:        publication.ThisUpdate,
		NextUpdate:        publication.NextUpdate,
		Status:            publication.Status,
		CRLPEM:            publication.CRLPEM,
		CreatedAt:         publication.CreatedAt,
		UpdatedAt:         publication.UpdatedAt,
	}
}

func toAuditEventResponse(event domain.AuditEvent) auditEventResponse {
	return auditEventResponse{
		ID:           event.ID,
		Actor:        event.Actor,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		MetadataJSON: event.MetadataJSON,
		CreatedAt:    event.CreatedAt,
	}
}

func toAuditEventResponses(events []domain.AuditEvent) []auditEventResponse {
	responses := make([]auditEventResponse, 0, len(events))
	for _, event := range events {
		responses = append(responses, toAuditEventResponse(event))
	}
	return responses
}
