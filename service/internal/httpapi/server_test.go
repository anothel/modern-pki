package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/corecli"
	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/lifecycle"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

var testNow = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func TestCreateIdentity(t *testing.T) {
	api := newTestAPI(t)

	var created apiIdentity
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type":        string(domain.IdentityMachine),
		"name":        "edge-01",
		"external_id": "asset-123",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created identity ID is empty")
	}
	if created.Type != domain.IdentityMachine {
		t.Fatalf("created identity type = %q, want %q", created.Type, domain.IdentityMachine)
	}
	if created.Name != "edge-01" {
		t.Fatalf("created identity name = %q, want %q", created.Name, "edge-01")
	}
	if created.Status != domain.IdentityActive {
		t.Fatalf("created identity status = %q, want %q", created.Status, domain.IdentityActive)
	}

	var listed []apiIdentity
	status = api.doJSON(t, http.MethodGet, "/identities", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("identity count = %d, want 1", len(listed))
	}
	if listed[0].ID != created.ID {
		t.Fatalf("listed identity ID = %q, want %q", listed[0].ID, created.ID)
	}

	var got apiIdentity
	status = api.doJSON(t, http.MethodGet, "/identities/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got identity ID = %q, want %q", got.ID, created.ID)
	}
}

func TestCreateIssuer(t *testing.T) {
	api := newTestAPI(t)

	var created apiIssuer
	status := api.doJSON(t, http.MethodPost, "/issuers", "admin", map[string]any{
		"name":            "intermediate-ca",
		"kind":            string(domain.IssuerIntermediateCA),
		"certificate_pem": "issuer-cert-pem",
		"key_ref":         "issuer-key-ref",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created issuer ID is empty")
	}
	if created.Name != "intermediate-ca" {
		t.Fatalf("created issuer name = %q, want %q", created.Name, "intermediate-ca")
	}
	if created.Kind != domain.IssuerIntermediateCA {
		t.Fatalf("created issuer kind = %q, want %q", created.Kind, domain.IssuerIntermediateCA)
	}
	if created.Status != domain.IssuerActive {
		t.Fatalf("created issuer status = %q, want %q", created.Status, domain.IssuerActive)
	}
}

func TestCreateAndListOCSPResponders(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-pem",
		"key_ref":         "responder-key",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created OCSP responder ID is empty")
	}
	if created.IssuerID != issuer.ID {
		t.Fatalf("created OCSP responder issuer ID = %q, want %q", created.IssuerID, issuer.ID)
	}
	if created.Name != "issuer-a-ocsp" {
		t.Fatalf("created OCSP responder name = %q, want %q", created.Name, "issuer-a-ocsp")
	}
	if created.Status != domain.OCSPResponderActive {
		t.Fatalf("created OCSP responder status = %q, want %q", created.Status, domain.OCSPResponderActive)
	}
	if created.CertificatePEM != "responder-pem" {
		t.Fatalf("created OCSP responder certificate = %q, want %q", created.CertificatePEM, "responder-pem")
	}
	if created.KeyRef != "responder-key" {
		t.Fatalf("created OCSP responder key ref = %q, want %q", created.KeyRef, "responder-key")
	}
	if len(api.issuer.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(api.issuer.ocspResponderValidationRequests))
	}
	validationReq := api.issuer.ocspResponderValidationRequests[0]
	if validationReq.issuerCertificatePEM != issuer.CertificatePEM {
		t.Fatalf("ValidateOCSPResponder issuer certificate = %q, want %q", validationReq.issuerCertificatePEM, issuer.CertificatePEM)
	}
	if validationReq.responderCertificatePEM != "responder-pem" {
		t.Fatalf("ValidateOCSPResponder responder certificate = %q, want %q", validationReq.responderCertificatePEM, "responder-pem")
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("OCSP responder count = %d, want 1", len(listed))
	}
	if listed[0].ID != created.ID {
		t.Fatalf("listed OCSP responder ID = %q, want %q", listed[0].ID, created.ID)
	}
}

func TestCreateOCSPResponderRejectsInvalidJSON(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", "not-an-object", &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestCreateOCSPResponderRequiresDisableBeforeReplacement(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	var body errorResponse
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusConflict)
	if body.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidTransition.Error())
	}
	if len(api.issuer.ocspResponderValidationRequests) != 1 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 1", len(api.issuer.ocspResponderValidationRequests))
	}
}

func TestDisableOCSPResponderAllowsReplacement(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)

	var disabled apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/"+first.ID+"/disable", "admin", nil, &disabled)
	assertStatus(t, status, http.StatusOK)
	if disabled.Status != domain.OCSPResponderDisabled {
		t.Fatalf("disabled responder status = %q, want %q", disabled.Status, domain.OCSPResponderDisabled)
	}

	var second apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &second)
	assertStatus(t, status, http.StatusCreated)
	if second.Status != domain.OCSPResponderActive {
		t.Fatalf("replacement responder status = %q, want %q", second.Status, domain.OCSPResponderActive)
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 2 {
		t.Fatalf("OCSP responder count = %d, want 2", len(listed))
	}
	if listed[0].Status != domain.OCSPResponderDisabled || listed[1].Status != domain.OCSPResponderActive {
		t.Fatalf("OCSP responder statuses = %#v", listed)
	}
}

func TestRotateOCSPResponder(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)

	var rotated apiOCSPResponder
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &rotated)
	assertStatus(t, status, http.StatusCreated)
	if rotated.ID == "" || rotated.ID == first.ID {
		t.Fatalf("rotated responder ID = %q, first ID = %q", rotated.ID, first.ID)
	}
	if rotated.IssuerID != issuer.ID ||
		rotated.Name != "issuer-b-ocsp" ||
		rotated.Status != domain.OCSPResponderActive ||
		rotated.CertificatePEM != "responder-b-pem" ||
		rotated.KeyRef != "responder-b-key" {
		t.Fatalf("rotated responder = %#v", rotated)
	}
	if len(api.issuer.ocspResponderValidationRequests) != 2 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 2", len(api.issuer.ocspResponderValidationRequests))
	}
	if got := api.issuer.ocspResponderValidationRequests[1].responderCertificatePEM; got != "responder-b-pem" {
		t.Fatalf("rotation validation responder certificate = %q, want responder-b-pem", got)
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	statuses := map[string]domain.OCSPResponderStatus{}
	for _, responder := range listed {
		statuses[responder.ID] = responder.Status
	}
	if statuses[first.ID] != domain.OCSPResponderDisabled || statuses[rotated.ID] != domain.OCSPResponderActive {
		t.Fatalf("OCSP responder statuses = %#v", statuses)
	}
}

func TestRotateOCSPResponderRequiresActiveResponder(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusConflict)
	if body.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidTransition.Error())
	}
	if len(api.issuer.ocspResponderValidationRequests) != 0 {
		t.Fatalf("ValidateOCSPResponder call count = %d, want 0", len(api.issuer.ocspResponderValidationRequests))
	}
}

func TestRotateOCSPResponderRejectsInvalidResponderValidation(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var first apiOCSPResponder
	status := api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders", "admin", map[string]any{
		"name":            "issuer-a-ocsp",
		"certificate_pem": "responder-a-pem",
		"key_ref":         "responder-a-key",
	}, &first)
	assertStatus(t, status, http.StatusCreated)
	api.issuer.ocspResponderValidationConfigured = true
	api.issuer.ocspResponderValidationResult = corecli.ValidateOCSPResponderResult{Valid: false}

	var body errorResponse
	status = api.doJSON(t, http.MethodPost, "/issuers/"+issuer.ID+"/ocsp-responders/rotate", "admin", map[string]any{
		"name":            "issuer-b-ocsp",
		"certificate_pem": "responder-b-pem",
		"key_ref":         "responder-b-key",
	}, &body)
	assertStatus(t, status, http.StatusUnprocessableEntity)
	if body.Error != domain.ErrOCSPResponderValidationFailed.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrOCSPResponderValidationFailed.Error())
	}

	var listed []apiOCSPResponder
	status = api.doJSON(t, http.MethodGet, "/issuers/"+issuer.ID+"/ocsp-responders", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != first.ID || listed[0].Status != domain.OCSPResponderActive {
		t.Fatalf("OCSP responders after failed rotate = %#v", listed)
	}
}

func TestCreateListAndDisableNotificationEndpoints(t *testing.T) {
	api := newTestAPI(t)

	var created apiNotificationEndpoint
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":        "ops-webhook",
		"url":         "https://ops.example.test/hooks/pki",
		"secret":      "super-secret",
		"event_types": []string{"certificate.expiration_warning", "certificate.expired"},
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created notification endpoint ID is empty")
	}
	if created.Name != "ops-webhook" ||
		created.Type != domain.NotificationEndpointWebhook ||
		created.Status != domain.NotificationEndpointActive ||
		created.URL != "https://ops.example.test/hooks/pki" ||
		len(created.EventTypes) != 2 {
		t.Fatalf("created notification endpoint = %#v", created)
	}

	var listed []apiNotificationEndpoint
	status = api.doJSON(t, http.MethodGet, "/notification-endpoints", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed notification endpoints = %#v", listed)
	}

	var disabled apiNotificationEndpoint
	status = api.doJSON(t, http.MethodPost, "/notification-endpoints/"+created.ID+"/disable", "admin", nil, &disabled)
	assertStatus(t, status, http.StatusOK)
	if disabled.Status != domain.NotificationEndpointDisabled {
		t.Fatalf("disabled notification endpoint status = %q, want disabled", disabled.Status)
	}
}

func TestCreateNotificationEndpointRequiresSecret(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name": "ops-webhook",
		"url":  "https://ops.example.test/hooks/pki",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestCreateNotificationEndpointDoesNotExposeSecret(t *testing.T) {
	api := newTestAPI(t)

	var created map[string]any
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":   "ops-webhook",
		"url":    "https://ops.example.test/hooks/pki",
		"secret": "super-secret",
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if _, ok := created["secret"]; ok {
		t.Fatalf("notification endpoint response exposed secret: %#v", created)
	}
}

func TestCreateNotificationEndpointRejectsInvalidURL(t *testing.T) {
	api := newTestAPI(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/notification-endpoints", "admin", map[string]any{
		"name":   "ops-webhook",
		"url":    "ftp://ops.example.test/hooks/pki",
		"secret": "super-secret",
	}, &body)
	assertStatus(t, status, http.StatusBadRequest)
	if body.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrInvalidRequest.Error())
	}
}

func TestListOutboxMessagesByStatusAndRetry(t *testing.T) {
	api := newTestAPI(t)
	message := domain.OutboxMessage{
		ID:           "outbox-dead",
		Type:         "certificate.expiration_warning",
		PayloadJSON:  `{"certificate_id":"cert-1"}`,
		Status:       domain.OutboxDeadLetter,
		AvailableAt:  testNow.Add(time.Hour),
		AttemptCount: 5,
		MaxAttempts:  5,
		LastError:    "webhook failed",
		CreatedAt:    testNow,
		UpdatedAt:    testNow,
	}
	if err := api.repo.CreateOutboxMessage(api.ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	var listed []apiOutboxMessage
	status := api.doJSON(t, http.MethodGet, "/outbox/messages?status=dead_letter", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 ||
		listed[0].ID != message.ID ||
		listed[0].Status != domain.OutboxDeadLetter ||
		listed[0].AttemptCount != 5 ||
		listed[0].LastError != "webhook failed" {
		t.Fatalf("listed outbox messages = %#v", listed)
	}

	var retried apiOutboxMessage
	status = api.doJSON(t, http.MethodPost, "/outbox/messages/"+message.ID+"/retry", "operator", nil, &retried)
	assertStatus(t, status, http.StatusOK)
	if retried.Status != domain.OutboxPending ||
		retried.AttemptCount != 0 ||
		retried.LastError != "" ||
		!retried.AvailableAt.Equal(testNow) {
		t.Fatalf("retried outbox message = %#v", retried)
	}
}

func TestCreateCertificateProfile(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var created apiCertificateProfile
	status := api.doJSON(t, http.MethodPost, "/certificate-profiles", "admin", map[string]any{
		"name":                    "machine-server",
		"description":             "Machine TLS server profile",
		"issuer_id":               issuer.ID,
		"validity_period_seconds": int64((24 * time.Hour).Seconds()),
		"subject_template":        "CN={{identity.name}}",
		"allowed_dns_patterns":    []string{"*.example.test"},
		"key_usage": map[string]any{
			"critical": true,
			"values":   []string{"digital_signature", "key_encipherment"},
		},
		"extended_key_usage": map[string]any{
			"critical": false,
			"values":   []string{"server_auth"},
		},
		"basic_constraints": map[string]any{
			"critical": true,
			"ca":       false,
		},
		"subject_key_identifier":   true,
		"authority_key_identifier": true,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.ID == "" {
		t.Fatal("created profile ID is empty")
	}
	if created.IssuerID != issuer.ID {
		t.Fatalf("created profile issuer ID = %q, want %q", created.IssuerID, issuer.ID)
	}
	if !created.KeyUsage.Critical || len(created.KeyUsage.Values) != 2 {
		t.Fatalf("created profile key usage = %#v", created.KeyUsage)
	}
	if !created.SubjectKeyIdentifier || !created.AuthorityKeyIdentifier {
		t.Fatalf("created profile key identifiers = ski:%t aki:%t", created.SubjectKeyIdentifier, created.AuthorityKeyIdentifier)
	}

	var listed []apiCertificateProfile
	status = api.doJSON(t, http.MethodGet, "/certificate-profiles", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("profile count = %d, want 1", len(listed))
	}

	var got apiCertificateProfile
	status = api.doJSON(t, http.MethodGet, "/certificate-profiles/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got profile ID = %q, want %q", got.ID, created.ID)
	}
}

func TestCreateEnrollment(t *testing.T) {
	api := newTestAPI(t)
	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	requestedNotAfter := testNow.Add(24 * time.Hour)

	var created apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/enrollments", "operator", map[string]any{
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"csr_pem":                "csr-pem",
		"requested_subject":      "CN=edge-01",
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    requestedNotAfter,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.Status != domain.EnrollmentPending {
		t.Fatalf("created enrollment status = %q, want %q", created.Status, domain.EnrollmentPending)
	}
	if created.IdentityID != identity.ID {
		t.Fatalf("created enrollment identity ID = %q, want %q", created.IdentityID, identity.ID)
	}
	if len(created.RequestedDNSNames) != 1 || created.RequestedDNSNames[0] != "edge-01.example.test" {
		t.Fatalf("created enrollment DNS names = %#v, want edge-01.example.test", created.RequestedDNSNames)
	}
	if len(created.CSRDNSNames) != 1 || created.CSRDNSNames[0] != "edge-01.example.test" {
		t.Fatalf("created enrollment CSR DNS names = %#v, want edge-01.example.test", created.CSRDNSNames)
	}

	var listed []apiEnrollment
	status = api.doJSON(t, http.MethodGet, "/enrollments", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("enrollment count = %d, want 1", len(listed))
	}

	var got apiEnrollment
	status = api.doJSON(t, http.MethodGet, "/enrollments/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got enrollment ID = %q, want %q", got.ID, created.ID)
	}
}

func TestApproveEnrollment(t *testing.T) {
	api := newTestAPI(t)
	enrollment := api.createPendingEnrollment(t)

	var approved apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/approve", "approver", nil, &approved)
	assertStatus(t, status, http.StatusOK)
	if approved.Status != domain.EnrollmentApproved {
		t.Fatalf("approved enrollment status = %q, want %q", approved.Status, domain.EnrollmentApproved)
	}
	if approved.ApprovedBy != "approver" {
		t.Fatalf("approved enrollment ApprovedBy = %q, want %q", approved.ApprovedBy, "approver")
	}

	var errorBody errorResponse
	status = api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/approve", "approver", nil, &errorBody)
	assertStatus(t, status, http.StatusConflict)
	if errorBody.Error != domain.ErrInvalidTransition.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrInvalidTransition.Error())
	}
}

func TestIssueCertificate(t *testing.T) {
	api := newTestAPI(t)
	enrollment := api.createApprovedEnrollment(t)

	var issued apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates", "issuer", map[string]string{
		"enrollment_id": enrollment.ID,
	}, &issued)
	assertStatus(t, status, http.StatusCreated)
	if issued.Status != domain.CertificateValid {
		t.Fatalf("issued certificate status = %q, want %q", issued.Status, domain.CertificateValid)
	}
	if issued.Subject != "CN=edge-01" {
		t.Fatalf("issued certificate subject = %q, want %q", issued.Subject, "CN=edge-01")
	}
	if issued.CertificatePEM != "issued:csr-pem" {
		t.Fatalf("issued certificate PEM = %q, want %q", issued.CertificatePEM, "issued:csr-pem")
	}
	if len(api.issuer.requests) != 1 {
		t.Fatalf("issuer request count = %d, want 1", len(api.issuer.requests))
	}

	var listed []apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 {
		t.Fatalf("certificate count = %d, want 1", len(listed))
	}

	var got apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates/"+issued.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != issued.ID {
		t.Fatalf("got certificate ID = %q, want %q", got.ID, issued.ID)
	}
}

func TestScanCertificateExpirations(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var result apiExpirationScanResult
	status := api.doJSON(t, http.MethodPost, "/certificates/expiration-scan", "scanner", map[string]any{
		"warning_window_seconds": int64((48 * time.Hour).Seconds()),
		"limit":                  10,
	}, &result)
	assertStatus(t, status, http.StatusOK)
	if len(result.Expired) != 0 {
		t.Fatalf("expired certificates = %#v, want none", result.Expired)
	}
	if len(result.ExpirationWarnings) != 1 || result.ExpirationWarnings[0].ID != certificate.ID {
		t.Fatalf("expiration warnings = %#v, want certificate %q", result.ExpirationWarnings, certificate.ID)
	}
	if result.ExpirationWarnings[0].RenewalNotifiedAt.IsZero() {
		t.Fatalf("warning RenewalNotifiedAt is zero: %#v", result.ExpirationWarnings[0])
	}

	var listed []apiCertificate
	status = api.doJSON(t, http.MethodGet, "/certificates", "", nil, &listed)
	assertStatus(t, status, http.StatusOK)
	if len(listed) != 1 || listed[0].ID != certificate.ID || listed[0].RenewalNotifiedAt.IsZero() {
		t.Fatalf("listed certificate after expiration scan = %#v", listed)
	}
}

func TestIssueCertificateHidesIssuerErrorCause(t *testing.T) {
	api := newTestAPI(t)
	api.issuer.err = errors.New("fake issuer detail")
	enrollment := api.createApprovedEnrollment(t)

	var errorBody errorResponse
	status := api.doJSON(t, http.MethodPost, "/certificates", "issuer", map[string]string{
		"enrollment_id": enrollment.ID,
	}, &errorBody)
	assertStatus(t, status, http.StatusBadGateway)
	if errorBody.Error != domain.ErrCertificateIssuanceFailed.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrCertificateIssuanceFailed.Error())
	}
}

func TestRevokeCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}
}

func TestSuspendResumeAndForceRevokeCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var suspended apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)
	if suspended.Status != domain.CertificateSuspended {
		t.Fatalf("suspended certificate status = %q, want %q", suspended.Status, domain.CertificateSuspended)
	}

	var resumed apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/resume", "operator", nil, &resumed)
	assertStatus(t, status, http.StatusOK)
	if resumed.Status != domain.CertificateValid {
		t.Fatalf("resumed certificate status = %q, want %q", resumed.Status, domain.CertificateValid)
	}

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)
	var revoked apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]any{
		"reason": string(domain.RevocationSuperseded),
		"force":  true,
	}, &revoked)
	assertStatus(t, status, http.StatusOK)
	if revoked.Status != domain.CertificateRevoked {
		t.Fatalf("force revoked certificate status = %q, want %q", revoked.Status, domain.CertificateRevoked)
	}
}

func TestRenewCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)
	requestedNotAfter := testNow.Add(90 * 24 * time.Hour)

	var renewal apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/renew", "operator", map[string]any{
		"csr_pem":             "renewal-csr-pem",
		"requested_not_after": requestedNotAfter,
	}, &renewal)
	assertStatus(t, status, http.StatusCreated)
	if renewal.Status != domain.EnrollmentPending {
		t.Fatalf("renewal status = %q, want %q", renewal.Status, domain.EnrollmentPending)
	}
	if renewal.IdentityID != certificate.IdentityID ||
		renewal.IssuerID != certificate.IssuerID ||
		renewal.CertificateProfileID != certificate.CertificateProfileID ||
		renewal.RequestedSubject != certificate.Subject ||
		renewal.CSRPEM != "renewal-csr-pem" {
		t.Fatalf("renewal = %#v, certificate = %#v", renewal, certificate)
	}
}

func TestReissueCertificate(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var reissue apiEnrollment
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/reissue", "operator", map[string]any{
		"csr_pem": "reissue-csr-pem",
	}, &reissue)
	assertStatus(t, status, http.StatusCreated)
	if reissue.Status != domain.EnrollmentPending {
		t.Fatalf("reissue status = %q, want %q", reissue.Status, domain.EnrollmentPending)
	}
	if reissue.IdentityID != certificate.IdentityID ||
		reissue.IssuerID != certificate.IssuerID ||
		reissue.CertificateProfileID != certificate.CertificateProfileID ||
		reissue.RequestedSubject != certificate.Subject ||
		reissue.CSRPEM != "reissue-csr-pem" ||
		!reissue.RequestedNotAfter.Equal(certificate.NotAfter) {
		t.Fatalf("reissue = %#v, certificate = %#v", reissue, certificate)
	}
}

func TestCertificateLifecycleRejectsInvalidTransitions(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var body errorResponse
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/resume", "operator", nil, &body)
	assertStatus(t, status, http.StatusConflict)

	var suspended apiCertificate
	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &suspended)
	assertStatus(t, status, http.StatusOK)

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/suspend", "operator", nil, &body)
	assertStatus(t, status, http.StatusConflict)

	status = api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationSuperseded),
	}, &body)
	assertStatus(t, status, http.StatusConflict)
}

func TestPublishCRL(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)

	var created apiCRLPublication
	nextUpdate := testNow.Add(24 * time.Hour)
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": "https://pki.example.test/intermediate.crl",
		"next_update":        nextUpdate,
	}, &created)
	assertStatus(t, status, http.StatusCreated)
	if created.IssuerID != certificate.IssuerID || created.CRLNumber != 1 || created.CRLPEM != "crl-pem" {
		t.Fatalf("created CRL = %#v", created)
	}

	var got apiCRLPublication
	status = api.doJSON(t, http.MethodGet, "/crls/"+created.ID, "", nil, &got)
	assertStatus(t, status, http.StatusOK)
	if got.ID != created.ID {
		t.Fatalf("got CRL ID = %q, want %q", got.ID, created.ID)
	}

	status, body, contentType := api.doRaw(t, http.MethodGet, "/issuers/"+certificate.IssuerID+"/crl", "")
	assertStatus(t, status, http.StatusOK)
	if string(body) != "crl-pem" {
		t.Fatalf("published CRL body = %q, want crl-pem", string(body))
	}
	if contentType != "application/x-pem-file" {
		t.Fatalf("published CRL content type = %q", contentType)
	}
}

func TestGetLatestIssuerCRLFiltersByDistributionPoint(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)

	var revoked apiCertificate
	status := api.doJSON(t, http.MethodPost, "/certificates/"+certificate.ID+"/revoke", "operator", map[string]string{
		"reason": string(domain.RevocationKeyCompromise),
	}, &revoked)
	assertStatus(t, status, http.StatusOK)

	dpA := "https://pki.example.test/a.crl"
	dpB := "https://pki.example.test/b.crl"
	nextUpdate := testNow.Add(24 * time.Hour)

	api.issuer.crlPEM = "crl-a"
	var crlA apiCRLPublication
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpA,
		"next_update":        nextUpdate,
	}, &crlA)
	assertStatus(t, status, http.StatusCreated)

	api.issuer.crlPEM = "crl-b"
	var crlB apiCRLPublication
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpB,
		"next_update":        nextUpdate,
	}, &crlB)
	assertStatus(t, status, http.StatusCreated)

	api.issuer.crlPEM = "crl-b-newer"
	status = api.doJSON(t, http.MethodPost, "/crls", "operator", map[string]any{
		"issuer_id":          certificate.IssuerID,
		"distribution_point": dpB,
		"next_update":        nextUpdate,
	}, &crlB)
	assertStatus(t, status, http.StatusCreated)

	status, body, _ := api.doRaw(t, http.MethodGet, "/issuers/"+certificate.IssuerID+"/crl?distribution_point="+url.QueryEscape(dpA), "")
	assertStatus(t, status, http.StatusOK)
	if string(body) != "crl-a" {
		t.Fatalf("published CRL body = %q, want crl-a", string(body))
	}
}

func TestRespondOCSP(t *testing.T) {
	api := newTestAPI(t)
	certificate := api.createCertificate(t)
	api.issuer.ocspInfo = corecli.OCSPRequestInfo{
		Certificates: []corecli.OCSPCertificateID{
			{SerialNumber: certificate.SerialNumber, IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash"},
		},
	}
	api.issuer.ocspResponseDER = []byte("ocsp-response-der")

	status, body, contentType := api.doBinary(t, http.MethodPost, "/ocsp", "operator", "application/ocsp-request", []byte("ocsp-request-der"))
	assertStatus(t, status, http.StatusOK)
	if string(body) != "ocsp-response-der" {
		t.Fatalf("OCSP response body = %q", string(body))
	}
	if contentType != "application/ocsp-response" {
		t.Fatalf("OCSP content type = %q", contentType)
	}
}

func TestRespondOCSPRejectsWrongContentType(t *testing.T) {
	api := newTestAPI(t)

	status, _, _ := api.doBinary(t, http.MethodPost, "/ocsp", "operator", "application/octet-stream", []byte("ocsp-request-der"))
	assertStatus(t, status, http.StatusUnsupportedMediaType)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	metadata := apiAuditMetadata(t, events[0])
	if events[0].Action != "api.request_failed" ||
		metadata["error_code"] != "unsupported_media_type" ||
		metadata["http_status"] != float64(http.StatusUnsupportedMediaType) {
		t.Fatalf("unsupported media audit = event:%#v metadata:%#v", events[0], metadata)
	}
}

func TestListAuditEvents(t *testing.T) {
	api := newTestAPI(t)
	issuer := api.createIssuer(t)

	var identity apiIdentity
	status := api.doJSON(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var enrollment apiEnrollment
	status = api.doJSON(t, http.MethodPost, "/enrollments", "operator", map[string]any{
		"identity_id":            identity.ID,
		"issuer_id":              issuer.ID,
		"csr_pem":                "csr-pem",
		"requested_subject":      "CN=edge-01",
		"requested_dns_names":    []string{"edge-01.example.test"},
		"requested_ip_addresses": []string{"127.0.0.1"},
		"requested_not_after":    testNow.Add(24 * time.Hour),
	}, &enrollment)
	assertStatus(t, status, http.StatusCreated)

	var rejected apiEnrollment
	status = api.doJSON(t, http.MethodPost, "/enrollments/"+enrollment.ID+"/reject", "reviewer", nil, &rejected)
	assertStatus(t, status, http.StatusOK)
	if rejected.Status != domain.EnrollmentRejected {
		t.Fatalf("rejected enrollment status = %q, want %q", rejected.Status, domain.EnrollmentRejected)
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)

	wantActions := []string{
		"issuer.created",
		"identity.created",
		"enrollment.created",
		"enrollment.rejected",
	}
	if len(events) != len(wantActions) {
		t.Fatalf("audit event count = %d, want %d", len(events), len(wantActions))
	}
	for i, want := range wantActions {
		if events[i].Action != want {
			t.Fatalf("audit event %d action = %q, want %q", i, events[i].Action, want)
		}
	}
	if events[1].Actor != "admin" {
		t.Fatalf("identity actor = %q, want %q", events[1].Actor, "admin")
	}
	if events[2].Actor != "operator" {
		t.Fatalf("enrollment actor = %q, want %q", events[2].Actor, "operator")
	}
	if events[3].Actor != "reviewer" {
		t.Fatalf("reject actor = %q, want %q", events[3].Actor, "reviewer")
	}
}

func TestAuditEventsIncludeRequestMetadata(t *testing.T) {
	api := newTestAPI(t)

	var identity apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
		"name": "edge-01",
	}, map[string]string{
		"X-Request-ID":    "req-123",
		"X-Forwarded-For": "203.0.113.10, 10.0.0.1",
	}, &identity)
	assertStatus(t, status, http.StatusCreated)

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	metadata := apiAuditMetadata(t, events[0])
	if metadata["request_id"] != "req-123" ||
		metadata["client_ip"] != "203.0.113.10" ||
		metadata["identity_id"] != identity.ID ||
		metadata["result_code"] != "ok" {
		t.Fatalf("audit metadata = %#v", metadata)
	}
}

func TestFailedRequestsCreateAuditEvents(t *testing.T) {
	api := newTestAPI(t)

	var errorBody errorResponse
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "admin", map[string]any{
		"type": string(domain.IdentityMachine),
	}, map[string]string{
		"X-Request-ID":    "req-failed",
		"X-Forwarded-For": "198.51.100.10",
	}, &errorBody)
	assertStatus(t, status, http.StatusBadRequest)
	if errorBody.Error != domain.ErrInvalidRequest.Error() {
		t.Fatalf("error body = %q, want %q", errorBody.Error, domain.ErrInvalidRequest.Error())
	}

	var events []apiAuditEvent
	status = api.doJSON(t, http.MethodGet, "/audit-events", "", nil, &events)
	assertStatus(t, status, http.StatusOK)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	event := events[0]
	if event.Action != "api.request_failed" || event.Actor != "admin" || event.ResourceType != "api" {
		t.Fatalf("failure audit event = %#v", event)
	}
	metadata := apiAuditMetadata(t, event)
	if metadata["result_code"] != "error" ||
		metadata["error_code"] != "invalid_request" ||
		metadata["request_id"] != "req-failed" ||
		metadata["client_ip"] != "198.51.100.10" ||
		metadata["http_method"] != http.MethodPost ||
		metadata["http_path"] != "/identities" ||
		metadata["http_status"] != float64(http.StatusBadRequest) {
		t.Fatalf("failure audit metadata = %#v", metadata)
	}
}

func TestAPIKeyAuthRejectsMissingBearerToken(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/identities", "", nil, &body)
	assertStatus(t, status, http.StatusUnauthorized)
	if body.Error != domain.ErrUnauthorized.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrUnauthorized.Error())
	}
}

func TestAPIKeyAuthRejectsInvalidBearerToken(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createTestAPIKey(t, api.repo, "key-1", "admin-token", "api-admin", domain.APIKeyActive)

	var body errorResponse
	status := api.doJSONWithHeaders(t, http.MethodGet, "/identities", "", nil, map[string]string{
		"Authorization": "Bearer wrong-token",
	}, &body)
	assertStatus(t, status, http.StatusUnauthorized)
	if body.Error != domain.ErrUnauthorized.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrUnauthorized.Error())
	}
}

func TestAPIKeyAuthUsesAPIKeyActorForMutations(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})
	createTestAPIKey(t, api.repo, "key-1", "admin-token", "api-admin", domain.APIKeyActive)

	var created apiIdentity
	status := api.doJSONWithHeaders(t, http.MethodPost, "/identities", "ignored-header-actor", map[string]any{
		"type":        string(domain.IdentityMachine),
		"name":        "edge-01",
		"external_id": "asset-123",
	}, map[string]string{
		"Authorization": "Bearer admin-token",
	}, &created)
	assertStatus(t, status, http.StatusCreated)

	events, err := api.repo.ListAuditEvents(api.ctx)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(events))
	}
	if events[0].Actor != "api-admin" {
		t.Fatalf("audit actor = %q, want api-admin", events[0].Actor)
	}
}

func TestAPIKeyAuthAllowsPublicCRLReads(t *testing.T) {
	api := newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeAPIKey})

	var body errorResponse
	status := api.doJSON(t, http.MethodGet, "/crls/missing-crl", "", nil, &body)
	assertStatus(t, status, http.StatusNotFound)
	if body.Error != domain.ErrCRLPublicationNotFound.Error() {
		t.Fatalf("error body = %q, want %q", body.Error, domain.ErrCRLPublicationNotFound.Error())
	}
}

type testAPI struct {
	ctx     context.Context
	client  *http.Client
	url     string
	repo    store.Repository
	service *lifecycle.Service
	issuer  *fakeIssuer
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	return newTestAPIWithAuth(t, AuthConfig{Mode: AuthModeDev})
}

func newTestAPIWithAuth(t *testing.T, auth AuthConfig) *testAPI {
	t.Helper()

	issuer := &fakeIssuer{}
	repo := store.NewMemoryStore()
	service := lifecycle.New(
		repo,
		issuer,
		fixedClock{now: testNow},
		&fakeIDGenerator{},
	)
	server := httptest.NewServer(NewWithAuth(service, auth))
	t.Cleanup(server.Close)

	return &testAPI{
		ctx:     context.Background(),
		client:  server.Client(),
		url:     server.URL,
		repo:    repo,
		service: service,
		issuer:  issuer,
	}
}

func createTestAPIKey(t *testing.T, repo store.Repository, id string, token string, actor string, status domain.APIKeyStatus) {
	t.Helper()
	if err := repo.CreateAPIKey(context.Background(), domain.APIKey{
		ID:        id,
		Name:      id,
		TokenHash: lifecycle.HashAPIKeyToken(token),
		Status:    status,
		Actor:     actor,
		CreatedAt: testNow,
		UpdatedAt: testNow,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}
}

func (api *testAPI) doJSON(t *testing.T, method string, path string, actor string, body any, into any) int {
	t.Helper()
	return api.doJSONWithHeaders(t, method, path, actor, body, nil, into)
}

func (api *testAPI) doJSONWithHeaders(t *testing.T, method string, path string, actor string, body any, headers map[string]string, into any) int {
	t.Helper()

	var requestBody *bytes.Reader
	if body == nil {
		requestBody = bytes.NewReader(nil)
	} else {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		requestBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, api.url+path, requestBody)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()

	if into != nil {
		if err := json.NewDecoder(res.Body).Decode(into); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
	return res.StatusCode
}

func (api *testAPI) doRaw(t *testing.T, method string, path string, actor string) (int, []byte, string) {
	t.Helper()

	req, err := http.NewRequest(method, api.url+path, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return res.StatusCode, body, res.Header.Get("Content-Type")
}

func (api *testAPI) doBinary(t *testing.T, method string, path string, actor string, contentType string, body []byte) (int, []byte, string) {
	t.Helper()

	req, err := http.NewRequest(method, api.url+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	res, err := api.client.Do(req)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}
	defer res.Body.Close()
	responseBody, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return res.StatusCode, responseBody, res.Header.Get("Content-Type")
}

func (api *testAPI) createIdentity(t *testing.T) domain.Identity {
	t.Helper()

	identity, err := api.service.CreateIdentity(api.ctx, "admin", lifecycle.CreateIdentityRequest{
		Type:       domain.IdentityMachine,
		Name:       "edge-01",
		ExternalID: "asset-123",
	})
	if err != nil {
		t.Fatalf("CreateIdentity returned error: %v", err)
	}
	return identity
}

func (api *testAPI) createIssuer(t *testing.T) domain.Issuer {
	t.Helper()

	issuer, err := api.service.CreateIssuer(api.ctx, "admin", lifecycle.CreateIssuerRequest{
		Name:           "intermediate-ca",
		Kind:           domain.IssuerIntermediateCA,
		CertificatePEM: "issuer-cert-pem",
		KeyRef:         "issuer-key-ref",
	})
	if err != nil {
		t.Fatalf("CreateIssuer returned error: %v", err)
	}
	return issuer
}

func (api *testAPI) createPendingEnrollment(t *testing.T) domain.Enrollment {
	t.Helper()

	identity := api.createIdentity(t)
	issuer := api.createIssuer(t)
	enrollment, err := api.service.CreateEnrollment(api.ctx, "operator", lifecycle.CreateEnrollmentRequest{
		IdentityID:           identity.ID,
		IssuerID:             issuer.ID,
		CSRPEM:               "csr-pem",
		RequestedSubject:     "CN=edge-01",
		RequestedDNSNames:    []string{"edge-01.example.test"},
		RequestedIPAddresses: []string{"127.0.0.1"},
		RequestedNotAfter:    testNow.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEnrollment returned error: %v", err)
	}
	return enrollment
}

func (api *testAPI) createApprovedEnrollment(t *testing.T) domain.Enrollment {
	t.Helper()

	enrollment := api.createPendingEnrollment(t)
	approved, err := api.service.ApproveEnrollment(api.ctx, "approver", enrollment.ID)
	if err != nil {
		t.Fatalf("ApproveEnrollment returned error: %v", err)
	}
	return approved
}

func (api *testAPI) createCertificate(t *testing.T) domain.Certificate {
	t.Helper()

	enrollment := api.createApprovedEnrollment(t)
	certificate, err := api.service.IssueCertificate(api.ctx, "issuer", enrollment.ID)
	if err != nil {
		t.Fatalf("IssueCertificate returned error: %v", err)
	}
	return certificate
}

func assertStatus(t *testing.T, got int, want int) {
	t.Helper()

	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

type fakeIssuer struct {
	requests                          []corecli.IssueRequest
	crlRequests                       []corecli.GenerateCRLRequest
	err                               error
	crlPEM                            string
	ocspInfo                          corecli.OCSPRequestInfo
	ocspResponses                     []corecli.GenerateOCSPResponseRequest
	ocspResponseDER                   []byte
	ocspResponderValidationRequests   []ocspResponderValidationRequest
	ocspResponderValidationConfigured bool
	ocspResponderValidationResult     corecli.ValidateOCSPResponderResult
}

func (f *fakeIssuer) InspectCSR(ctx context.Context, csrPEM string) (corecli.CSRInfo, error) {
	return corecli.CSRInfo{
		Subject:     "CN=edge-01",
		DNSNames:    []string{"edge-01.example.test"},
		IPAddresses: []string{"127.0.0.1"},
	}, nil
}

func (f *fakeIssuer) Issue(ctx context.Context, req corecli.IssueRequest) (corecli.IssueResult, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return corecli.IssueResult{}, f.err
	}
	return corecli.IssueResult{
		CertificatePEM: "issued:" + req.CSRPEM,
		SerialNumber:   "serial:" + req.Subject,
		Subject:        req.Subject,
		NotBefore:      req.NotBefore,
		NotAfter:       req.NotAfter,
	}, nil
}

func (f *fakeIssuer) GenerateCRL(ctx context.Context, req corecli.GenerateCRLRequest) (corecli.GenerateCRLResult, error) {
	f.crlRequests = append(f.crlRequests, req)
	if f.err != nil {
		return corecli.GenerateCRLResult{}, f.err
	}
	crlPEM := f.crlPEM
	if crlPEM == "" {
		crlPEM = "crl-pem"
	}
	return corecli.GenerateCRLResult{CRLPEM: crlPEM}, nil
}

func (f *fakeIssuer) InspectOCSPIssuer(ctx context.Context, issuerCertificatePEM string, hashAlgorithm string) (corecli.OCSPIssuerInfo, error) {
	if f.err != nil {
		return corecli.OCSPIssuerInfo{}, f.err
	}
	return corecli.OCSPIssuerInfo{IssuerNameHash: "name-hash", IssuerKeyHash: "key-hash", HashAlgorithm: hashAlgorithm}, nil
}

func (f *fakeIssuer) ValidateOCSPResponder(ctx context.Context, issuerCertificatePEM string, responderCertificatePEM string) (corecli.ValidateOCSPResponderResult, error) {
	f.ocspResponderValidationRequests = append(f.ocspResponderValidationRequests, ocspResponderValidationRequest{
		issuerCertificatePEM:    issuerCertificatePEM,
		responderCertificatePEM: responderCertificatePEM,
	})
	if f.err != nil {
		return corecli.ValidateOCSPResponderResult{}, f.err
	}
	if !f.ocspResponderValidationConfigured {
		return corecli.ValidateOCSPResponderResult{Valid: true}, nil
	}
	return f.ocspResponderValidationResult, nil
}

func (f *fakeIssuer) InspectOCSP(ctx context.Context, requestDER []byte) (corecli.OCSPRequestInfo, error) {
	if f.err != nil {
		return corecli.OCSPRequestInfo{}, f.err
	}
	return f.ocspInfo, nil
}

func (f *fakeIssuer) GenerateOCSPResponse(ctx context.Context, req corecli.GenerateOCSPResponseRequest) (corecli.GenerateOCSPResponseResult, error) {
	f.ocspResponses = append(f.ocspResponses, req)
	if f.err != nil {
		return corecli.GenerateOCSPResponseResult{}, f.err
	}
	return corecli.GenerateOCSPResponseResult{ResponseDER: f.ocspResponseDER}, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type fakeIDGenerator struct {
	next int
}

func (g *fakeIDGenerator) NewID() string {
	g.next++
	return fmt.Sprintf("id-%d", g.next)
}

type apiIdentity struct {
	ID         string                `json:"id"`
	Type       domain.IdentityType   `json:"type"`
	Name       string                `json:"name"`
	ExternalID string                `json:"external_id"`
	Status     domain.IdentityStatus `json:"status"`
	CreatedAt  time.Time             `json:"created_at"`
	UpdatedAt  time.Time             `json:"updated_at"`
}

type apiIssuer struct {
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Kind           domain.IssuerKind   `json:"kind"`
	Status         domain.IssuerStatus `json:"status"`
	CertificatePEM string              `json:"certificate_pem"`
	KeyRef         string              `json:"key_ref"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
}

type apiOCSPResponder struct {
	ID             string                     `json:"id"`
	IssuerID       string                     `json:"issuer_id"`
	Name           string                     `json:"name"`
	Status         domain.OCSPResponderStatus `json:"status"`
	CertificatePEM string                     `json:"certificate_pem"`
	KeyRef         string                     `json:"key_ref"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
}

type apiNotificationEndpoint struct {
	ID         string                            `json:"id"`
	Name       string                            `json:"name"`
	Type       domain.NotificationEndpointType   `json:"type"`
	Status     domain.NotificationEndpointStatus `json:"status"`
	URL        string                            `json:"url"`
	EventTypes []string                          `json:"event_types"`
	CreatedAt  time.Time                         `json:"created_at"`
	UpdatedAt  time.Time                         `json:"updated_at"`
}

type apiOutboxMessage struct {
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

type apiCertificateProfile struct {
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

type apiEnrollment struct {
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

type apiCertificate struct {
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

type apiExpirationScanResult struct {
	Expired            []apiCertificate `json:"expired"`
	ExpirationWarnings []apiCertificate `json:"expiration_warnings"`
}

type apiCRLPublication struct {
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

type apiAuditEvent struct {
	ID           string    `json:"id"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	MetadataJSON string    `json:"metadata_json"`
	CreatedAt    time.Time `json:"created_at"`
}

type ocspResponderValidationRequest struct {
	issuerCertificatePEM    string
	responderCertificatePEM string
}

func apiAuditMetadata(t *testing.T, event apiAuditEvent) map[string]any {
	t.Helper()

	var metadata map[string]any
	if err := json.Unmarshal([]byte(event.MetadataJSON), &metadata); err != nil {
		t.Fatalf("unmarshal audit metadata for %s: %v", event.Action, err)
	}
	return metadata
}
