package lifecycle

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

func TestWebhookOutboxHandlerPostsMatchingActiveEndpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()

	var received webhookDeliveryRequest
	var signature string
	var timestamp string
	var eventType string
	var deliveryID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		signature = r.Header.Get("X-Modern-PKI-Signature")
		timestamp = r.Header.Get("X-Modern-PKI-Timestamp")
		eventType = r.Header.Get("X-Modern-PKI-Event")
		deliveryID = r.Header.Get("X-Modern-PKI-Delivery")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read webhook body: %v", err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("decode webhook body: %v", err)
		}
		wantSignature := webhookSignature("secret-1", timestamp, body)
		if signature != wantSignature {
			t.Fatalf("signature = %q, want %q", signature, wantSignature)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:         "endpoint-1",
		Name:       "ops",
		Type:       domain.NotificationEndpointWebhook,
		Status:     domain.NotificationEndpointActive,
		URL:        server.URL,
		Secret:     "secret-1",
		EventTypes: []string{"certificate.expiration_warning"},
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if received.OutboxMessageID != "outbox-1" ||
		received.EventType != "certificate.expiration_warning" ||
		received.CreatedAt != now {
		t.Fatalf("webhook body = %#v", received)
	}
	if eventType != "certificate.expiration_warning" || deliveryID != "outbox-1" || timestamp == "" {
		t.Fatalf("webhook headers event=%q delivery=%q timestamp=%q", eventType, deliveryID, timestamp)
	}
	if got := received.Payload["certificate_id"]; got != "cert-1" {
		t.Fatalf("payload certificate_id = %#v, want cert-1", got)
	}
}

func TestWebhookOutboxHandlerAllowsLegacyEndpointWithoutSecret(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	var signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signature = r.Header.Get("X-Modern-PKI-Signature")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "legacy",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if signature != "" {
		t.Fatalf("legacy endpoint signature = %q, want empty", signature)
	}
}

func TestWebhookOutboxHandlerSkipsDisabledAndFilteredEndpoints(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	endpoints := []domain.NotificationEndpoint{
		{
			ID:         "disabled",
			Name:       "disabled",
			Type:       domain.NotificationEndpointWebhook,
			Status:     domain.NotificationEndpointDisabled,
			URL:        server.URL,
			Secret:     "secret-disabled",
			EventTypes: nil,
			CreatedAt:  now,
			UpdatedAt:  now,
		},
		{
			ID:         "filtered",
			Name:       "filtered",
			Type:       domain.NotificationEndpointWebhook,
			Status:     domain.NotificationEndpointActive,
			URL:        server.URL,
			Secret:     "secret-filtered",
			EventTypes: []string{"certificate.expired"},
			CreatedAt:  now.Add(time.Second),
			UpdatedAt:  now.Add(time.Second),
		},
	}
	for _, endpoint := range endpoints {
		if err := repo.CreateNotificationEndpoint(ctx, endpoint); err != nil {
			t.Fatalf("CreateNotificationEndpoint(%s) returned error: %v", endpoint.ID, err)
		}
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatalf("HandleOutboxMessage returned error: %v", err)
	}
	if requests != 0 {
		t.Fatalf("webhook request count = %d, want 0", requests)
	}
}

func TestWebhookOutboxHandlerReturnsErrorOnHTTPFailure(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "ops",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		Secret:    "secret-1",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, server.Client())
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("HandleOutboxMessage error = %v, want HTTP 500 error", err)
	}
}

func TestWebhookOutboxHandlerDefaultClientRejectsUnsafeEndpoint(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	repo := store.NewMemoryStore()
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := repo.CreateNotificationEndpoint(ctx, domain.NotificationEndpoint{
		ID:        "endpoint-1",
		Name:      "unsafe",
		Type:      domain.NotificationEndpointWebhook,
		Status:    domain.NotificationEndpointActive,
		URL:       server.URL,
		Secret:    "secret-1",
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNotificationEndpoint returned error: %v", err)
	}

	handler := NewWebhookOutboxHandler(repo, nil)
	err := handler.HandleOutboxMessage(ctx, domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiration_warning",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		CreatedAt:   now,
	})
	if err == nil {
		t.Fatal("HandleOutboxMessage returned nil error, want unsafe target rejection")
	}
	if requests != 0 {
		t.Fatalf("unsafe webhook requests = %d, want 0", requests)
	}
}

func webhookSignature(secret string, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
