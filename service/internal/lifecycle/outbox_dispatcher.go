package lifecycle

import (
	"context"
	"errors"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

type OutboxHandler interface {
	HandleOutboxMessage(context.Context, domain.OutboxMessage) error
}

type OutboxHandlerFunc func(context.Context, domain.OutboxMessage) error

func (fn OutboxHandlerFunc) HandleOutboxMessage(ctx context.Context, message domain.OutboxMessage) error {
	return fn(ctx, message)
}

type OutboxDispatcher struct {
	repo    store.Repository
	handler OutboxHandler
	clock   Clock
	idgen   IDGenerator
}

func NewOutboxDispatcher(repo store.Repository, handler OutboxHandler, clock Clock, idgen IDGenerator) *OutboxDispatcher {
	return &OutboxDispatcher{
		repo:    repo,
		handler: handler,
		clock:   clock,
		idgen:   idgen,
	}
}

func (d *OutboxDispatcher) RunOnce(ctx context.Context, limit int) (int, error) {
	messages, err := d.repo.ListDueOutboxMessages(ctx, d.clock.Now(), limit)
	if err != nil {
		return 0, err
	}

	processed := 0
	for _, message := range messages {
		claimed, err := d.claim(ctx, message)
		if err != nil {
			return processed, err
		}
		if !claimed {
			continue
		}

		startedAt := d.clock.Now()
		handlerErr := d.handler.HandleOutboxMessage(ctx, message)
		finishedAt := d.clock.Now()

		attemptStatus := domain.JobAttemptSucceeded
		nextStatus := domain.OutboxCompleted
		errorMessage := ""
		if handlerErr != nil {
			attemptStatus = domain.JobAttemptFailed
			nextStatus = domain.OutboxFailed
			errorMessage = handlerErr.Error()
		}

		if err := d.finish(ctx, message, nextStatus, domain.JobAttempt{
			ID:              d.idgen.NewID(),
			OutboxMessageID: message.ID,
			Status:          attemptStatus,
			Error:           errorMessage,
			StartedAt:       startedAt,
			FinishedAt:      finishedAt,
			CreatedAt:       finishedAt,
		}); err != nil {
			return processed, err
		}
		processed++
	}
	return processed, nil
}

func (d *OutboxDispatcher) claim(ctx context.Context, message domain.OutboxMessage) (bool, error) {
	claimed := message
	claimed.Status = domain.OutboxProcessing
	claimed.UpdatedAt = d.clock.Now()
	err := d.repo.UpdateOutboxMessageStatusIfStatus(ctx, claimed, domain.OutboxPending)
	if errors.Is(err, domain.ErrInvalidTransition) || errors.Is(err, domain.ErrOutboxMessageNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (d *OutboxDispatcher) finish(ctx context.Context, message domain.OutboxMessage, status domain.OutboxMessageStatus, attempt domain.JobAttempt) error {
	return d.repo.WithinTx(ctx, func(repo store.Repository) error {
		finished := message
		finished.Status = status
		finished.UpdatedAt = attempt.FinishedAt
		if err := repo.UpdateOutboxMessageStatusIfStatus(ctx, finished, domain.OutboxProcessing); err != nil {
			return err
		}
		return repo.CreateJobAttempt(ctx, attempt)
	})
}
