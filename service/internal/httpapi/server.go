package httpapi

import (
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
}

func New(service *lifecycle.Service) *Server {
	s := &Server{
		service: service,
		mux:     http.NewServeMux(),
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
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("POST /identities", s.createIdentity)
	s.mux.HandleFunc("GET /identities", s.listIdentities)
	s.mux.HandleFunc("GET /identities/{id}", s.getIdentity)

	s.mux.HandleFunc("POST /issuers", s.createIssuer)

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
	s.mux.HandleFunc("GET /certificates/{id}", s.getCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/revoke", s.revokeCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/suspend", s.suspendCertificate)
	s.mux.HandleFunc("POST /certificates/{id}/resume", s.resumeCertificate)

	s.mux.HandleFunc("POST /crls", s.publishCRL)
	s.mux.HandleFunc("GET /crls/{id}", s.getCRLPublication)
	s.mux.HandleFunc("GET /issuers/{id}/crl", s.getLatestIssuerCRL)

	s.mux.HandleFunc("POST /ocsp", s.respondOCSP)

	s.mux.HandleFunc("GET /audit-events", s.listAuditEvents)
}

func (s *Server) createIdentity(w http.ResponseWriter, r *http.Request) {
	var req createIdentityRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	identity, err := s.service.CreateIdentity(r.Context(), requestActor(r), lifecycle.CreateIdentityRequest{
		Type:       req.Type,
		Name:       req.Name,
		ExternalID: req.ExternalID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIdentityResponse(identity))
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) {
	identities, err := s.service.ListIdentities(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponses(identities))
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request) {
	identity, err := s.service.GetIdentity(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toIdentityResponse(identity))
}

func (s *Server) createIssuer(w http.ResponseWriter, r *http.Request) {
	var req createIssuerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	issuer, err := s.service.CreateIssuer(r.Context(), requestActor(r), lifecycle.CreateIssuerRequest{
		Name:           req.Name,
		Kind:           req.Kind,
		CertificatePEM: req.CertificatePEM,
		KeyRef:         req.KeyRef,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toIssuerResponse(issuer))
}

func (s *Server) createCertificateProfile(w http.ResponseWriter, r *http.Request) {
	var req createCertificateProfileRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
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
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateProfileResponse(profile))
}

func (s *Server) listCertificateProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := s.service.ListCertificateProfiles(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponses(profiles))
}

func (s *Server) getCertificateProfile(w http.ResponseWriter, r *http.Request) {
	profile, err := s.service.GetCertificateProfile(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateProfileResponse(profile))
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req createEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
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
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toEnrollmentResponse(enrollment))
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	enrollments, err := s.service.ListEnrollments(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponses(enrollments))
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.GetEnrollment(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) approveEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.ApproveEnrollment(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) rejectEnrollment(w http.ResponseWriter, r *http.Request) {
	enrollment, err := s.service.RejectEnrollment(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toEnrollmentResponse(enrollment))
}

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	var req issueCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	certificate, err := s.service.IssueCertificate(r.Context(), requestActor(r), req.EnrollmentID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCertificateResponse(certificate))
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	certificates, err := s.service.ListCertificates(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponses(certificates))
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.GetCertificate(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) revokeCertificate(w http.ResponseWriter, r *http.Request) {
	var req revokeCertificateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
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
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) suspendCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.SuspendCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) resumeCertificate(w http.ResponseWriter, r *http.Request) {
	certificate, err := s.service.ResumeCertificate(r.Context(), requestActor(r), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toCertificateResponse(certificate))
}

func (s *Server) publishCRL(w http.ResponseWriter, r *http.Request) {
	var req publishCRLRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	publication, err := s.service.PublishCRL(r.Context(), requestActor(r), lifecycle.PublishCRLRequest{
		IssuerID:          req.IssuerID,
		DistributionPoint: req.DistributionPoint,
		NextUpdate:        req.NextUpdate,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toCRLPublicationResponse(publication))
}

func (s *Server) getCRLPublication(w http.ResponseWriter, r *http.Request) {
	publication, err := s.service.GetCRLPublication(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
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
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(publication.CRLPEM))
}

func (s *Server) respondOCSP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{Error: "unsupported media type"})
		return
	}
	requestDER, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, domain.ErrInvalidRequest)
		return
	}
	response, err := s.service.RespondOCSP(r.Context(), requestActor(r), requestDER)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response.ResponseDER)
}

func (s *Server) listAuditEvents(w http.ResponseWriter, r *http.Request) {
	events, err := s.service.ListAuditEvents(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toAuditEventResponses(events))
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
	actor := r.Header.Get("X-Actor")
	if actor == "" {
		return "anonymous"
	}
	return actor
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

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, statusForError(err), errorResponse{Error: publicErrorMessage(err)})
}

func publicErrorMessage(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidRequest):
		return domain.ErrInvalidRequest.Error()
	case errors.Is(err, domain.ErrInvalidTransition):
		return domain.ErrInvalidTransition.Error()
	case errors.Is(err, domain.ErrIdentityNotFound):
		return domain.ErrIdentityNotFound.Error()
	case errors.Is(err, domain.ErrIssuerNotFound):
		return domain.ErrIssuerNotFound.Error()
	case errors.Is(err, domain.ErrCertificateProfileNotFound):
		return domain.ErrCertificateProfileNotFound.Error()
	case errors.Is(err, domain.ErrEnrollmentNotFound):
		return domain.ErrEnrollmentNotFound.Error()
	case errors.Is(err, domain.ErrCertificateNotFound):
		return domain.ErrCertificateNotFound.Error()
	case errors.Is(err, domain.ErrCRLPublicationNotFound):
		return domain.ErrCRLPublicationNotFound.Error()
	case errors.Is(err, domain.ErrCSRParseFailed):
		return domain.ErrCSRParseFailed.Error()
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return domain.ErrCertificateIssuanceFailed.Error()
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return domain.ErrCRLGenerationFailed.Error()
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return domain.ErrOCSPDecodeFailed.Error()
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
	case errors.Is(err, domain.ErrInvalidTransition):
		return http.StatusConflict
	case errors.Is(err, domain.ErrIdentityNotFound),
		errors.Is(err, domain.ErrIssuerNotFound),
		errors.Is(err, domain.ErrCertificateProfileNotFound),
		errors.Is(err, domain.ErrEnrollmentNotFound),
		errors.Is(err, domain.ErrCertificateNotFound),
		errors.Is(err, domain.ErrCRLPublicationNotFound):
		return http.StatusNotFound
	case errors.Is(err, domain.ErrCSRParseFailed):
		return http.StatusUnprocessableEntity
	case errors.Is(err, domain.ErrCertificateIssuanceFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrCRLGenerationFailed):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrOCSPDecodeFailed):
		return http.StatusBadRequest
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
	Name           string            `json:"name"`
	Kind           domain.IssuerKind `json:"kind"`
	CertificatePEM string            `json:"certificate_pem"`
	KeyRef         string            `json:"key_ref"`
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
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Kind           domain.IssuerKind   `json:"kind"`
	Status         domain.IssuerStatus `json:"status"`
	CertificatePEM string              `json:"certificate_pem"`
	KeyRef         string              `json:"key_ref"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
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
	CreatedAt            time.Time                `json:"created_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
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
		ID:             issuer.ID,
		Name:           issuer.Name,
		Kind:           issuer.Kind,
		Status:         issuer.Status,
		CertificatePEM: issuer.CertificatePEM,
		KeyRef:         issuer.KeyRef,
		CreatedAt:      issuer.CreatedAt,
		UpdatedAt:      issuer.UpdatedAt,
	}
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
