package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

func TestOutboxDispatcherCompletesHandledMessage(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: clock.now.Add(-time.Minute),
		CreatedAt:   clock.now.Add(-time.Minute),
		UpdatedAt:   clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}

	handled := make([]domain.OutboxMessage, 0)
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		handled = append(handled, message)
		return nil
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	if len(handled) != 1 || handled[0].ID != message.ID {
		t.Fatalf("handled messages = %#v", handled)
	}
	due, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due messages after success = %#v, want none", due)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != domain.JobAttemptSucceeded || attempts[0].Error != "" {
		t.Fatalf("attempts = %#v, want one success", attempts)
	}
}

func TestOutboxDispatcherRecordsFailure(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemoryStore()
	clock := fixedClock{now: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	message := domain.OutboxMessage{
		ID:          "outbox-1",
		Type:        "certificate.expiring",
		PayloadJSON: `{"certificate_id":"cert-1"}`,
		Status:      domain.OutboxPending,
		AvailableAt: clock.now.Add(-time.Minute),
		CreatedAt:   clock.now.Add(-time.Minute),
		UpdatedAt:   clock.now.Add(-time.Minute),
	}
	if err := repo.CreateOutboxMessage(ctx, message); err != nil {
		t.Fatalf("CreateOutboxMessage returned error: %v", err)
	}
	errNotify := errors.New("notify failed")
	dispatcher := NewOutboxDispatcher(repo, OutboxHandlerFunc(func(ctx context.Context, message domain.OutboxMessage) error {
		return errNotify
	}), clock, &fakeIDGenerator{})

	processed, err := dispatcher.RunOnce(ctx, 10)
	if err != nil {
		t.Fatalf("RunOnce returned error: %v", err)
	}
	if processed != 1 {
		t.Fatalf("processed = %d, want 1", processed)
	}
	due, err := repo.ListDueOutboxMessages(ctx, clock.now, 10)
	if err != nil {
		t.Fatalf("ListDueOutboxMessages returned error: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due messages after failure = %#v, want none", due)
	}
	attempts, err := repo.ListJobAttemptsByOutboxMessage(ctx, message.ID)
	if err != nil {
		t.Fatalf("ListJobAttemptsByOutboxMessage returned error: %v", err)
	}
	if len(attempts) != 1 || attempts[0].Status != domain.JobAttemptFailed || attempts[0].Error != "notify failed" {
		t.Fatalf("attempts = %#v, want one failed attempt", attempts)
	}
}
