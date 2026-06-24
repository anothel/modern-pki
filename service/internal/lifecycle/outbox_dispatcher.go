package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/domain"
	"github.com/modern-pki/modern-pki/service/internal/store"
)

const (
	defaultOutboxMaxAttempts     = 5
	defaultOutboxProcessingLease = 10 * time.Minute
)

var outboxRetryDelays = []time.Duration{
	time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	time.Hour,
}

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
		claimed, ok, err := d.claim(ctx, message)
		if err != nil {
			return processed, err
		}
		if !ok {
			continue
		}

		startedAt := d.clock.Now()
		handlerErr := d.handler.HandleOutboxMessage(ctx, claimed)
		finishedAt := d.clock.Now()

		attemptStatus := domain.JobAttemptSucceeded
		nextStatus := domain.OutboxCompleted
		errorMessage := ""
		if handlerErr != nil {
			attemptStatus = domain.JobAttemptFailed
			errorMessage = handlerErr.Error()
			claimed.AttemptCount++
			claimed.MaxAttempts = effectiveOutboxMaxAttempts(claimed)
			claimed.LastError = errorMessage
			if claimed.AttemptCount >= claimed.MaxAttempts {
				nextStatus = domain.OutboxDeadLetter
			} else {
				nextStatus = domain.OutboxPending
				claimed.AvailableAt = finishedAt.Add(outboxRetryDelayForAttempt(claimed.AttemptCount))
			}
		} else {
			claimed.LastError = ""
		}

		if err := d.finish(ctx, claimed, nextStatus, domain.JobAttempt{
			ID:              d.idgen.NewID(),
			OutboxMessageID: claimed.ID,
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

func effectiveOutboxMaxAttempts(message domain.OutboxMessage) int {
	if message.MaxAttempts > 0 {
		return message.MaxAttempts
	}
	return defaultOutboxMaxAttempts
}

func outboxRetryDelayForAttempt(attemptCount int) time.Duration {
	if attemptCount <= 1 {
		return outboxRetryDelays[0]
	}
	index := attemptCount - 1
	if index >= len(outboxRetryDelays) {
		index = len(outboxRetryDelays) - 1
	}
	return outboxRetryDelays[index]
}

func (d *OutboxDispatcher) claim(ctx context.Context, message domain.OutboxMessage) (domain.OutboxMessage, bool, error) {
	currentStatus := message.Status
	if currentStatus != domain.OutboxPending && currentStatus != domain.OutboxProcessing {
		return domain.OutboxMessage{}, false, nil
	}
	now := d.clock.Now()
	if currentStatus == domain.OutboxProcessing {
		recovered := message
		recovered.Status = domain.OutboxPending
		recovered.ProcessingDeadlineAt = time.Time{}
		recovered.UpdatedAt = now
		err := d.repo.UpdateOutboxMessageIfCurrent(ctx, recovered, message)
		if errors.Is(err, domain.ErrInvalidTransition) || errors.Is(err, domain.ErrOutboxMessageNotFound) {
			return domain.OutboxMessage{}, false, nil
		}
		if err != nil {
			return domain.OutboxMessage{}, false, err
		}
		message = recovered
	}
	claimed := message
	claimed.Status = domain.OutboxProcessing
	claimed.ProcessingDeadlineAt = now.Add(defaultOutboxProcessingLease)
	claimed.UpdatedAt = now
	err := d.repo.UpdateOutboxMessageIfCurrent(ctx, claimed, message)
	if errors.Is(err, domain.ErrInvalidTransition) || errors.Is(err, domain.ErrOutboxMessageNotFound) {
		return domain.OutboxMessage{}, false, nil
	}
	if err != nil {
		return domain.OutboxMessage{}, false, err
	}
	return claimed, true, nil
}

func (d *OutboxDispatcher) finish(ctx context.Context, message domain.OutboxMessage, status domain.OutboxMessageStatus, attempt domain.JobAttempt) error {
	return d.repo.WithinTx(ctx, func(repo store.Repository) error {
		finished := message
		finished.Status = status
		finished.ProcessingDeadlineAt = time.Time{}
		finished.UpdatedAt = attempt.FinishedAt
		if err := repo.UpdateOutboxMessageIfCurrent(ctx, finished, message); err != nil {
			return err
		}
		return repo.CreateJobAttempt(ctx, attempt)
	})
}
