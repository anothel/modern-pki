package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

type webhookDeliveryRequest struct {
	OutboxMessageID string         `json:"outbox_message_id"`
	EventType       string         `json:"event_type"`
	Payload         map[string]any `json:"payload"`
	CreatedAt       time.Time      `json:"created_at"`
}

type WebhookOutboxHandler struct {
	repo       store.NotificationEndpointRepository
	httpClient *http.Client
}

func NewWebhookOutboxHandler(repo store.NotificationEndpointRepository, httpClient *http.Client) *WebhookOutboxHandler {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &WebhookOutboxHandler{
		repo:       repo,
		httpClient: httpClient,
	}
}

func (h *WebhookOutboxHandler) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	endpoints, err := h.repo.ListNotificationEndpoints(ctx)
	if err != nil {
		return err
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(message.PayloadJSON), &payload); err != nil {
		return fmt.Errorf("decode outbox payload: %w", err)
	}
	body := webhookDeliveryRequest{
		OutboxMessageID: message.ID,
		EventType:       message.Type,
		Payload:         payload,
		CreatedAt:       message.CreatedAt,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	for _, endpoint := range endpoints {
		if !webhookEndpointMatches(endpoint, message.Type) {
			continue
		}
		if err := h.postWebhook(ctx, endpoint.URL, data); err != nil {
			return err
		}
	}
	return nil
}

func (h *WebhookOutboxHandler) postWebhook(ctx context.Context, endpointURL string, data []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := h.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("webhook delivery failed: %s", res.Status)
	}
	return nil
}

func webhookEndpointMatches(endpoint domain.NotificationEndpoint, eventType string) bool {
	if endpoint.Type != domain.NotificationEndpointWebhook || endpoint.Status != domain.NotificationEndpointActive {
		return false
	}
	if len(endpoint.EventTypes) == 0 {
		return true
	}
	for _, candidate := range endpoint.EventTypes {
		if candidate == eventType {
			return true
		}
	}
	return false
}
