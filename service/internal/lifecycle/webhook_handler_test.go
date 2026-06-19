package lifecycle

import (
	"context"
	"encoding/json"
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("content type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode webhook body: %v", err)
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
	if got := received.Payload["certificate_id"]; got != "cert-1" {
		t.Fatalf("payload certificate_id = %#v, want cert-1", got)
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
