package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/corecli"
	"github.com/modern-pki/modern-pki/service/internal/httpapi"
	"github.com/modern-pki/modern-pki/service/internal/lifecycle"
	"github.com/modern-pki/modern-pki/service/internal/store"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

const (
	defaultAddr     = ":8080"
	defaultDBDriver = "sqlite"
	defaultDBDSN    = "modern-pki.db"
	defaultCoreBin  = "modern-pki-core"

	defaultOutboxEnabled   = true
	defaultOutboxInterval  = 5 * time.Second
	defaultOutboxBatchSize = 10
)

type outboxConfig struct {
	Enabled   bool
	Interval  time.Duration
	BatchSize int
}

func main() {
	addr := envOrDefault("MODERN_PKI_ADDR", defaultAddr)
	dbDriver := envOrDefault("MODERN_PKI_DB_DRIVER", defaultDBDriver)
	dbDSN := envOrDefault("MODERN_PKI_DB_DSN", defaultDBDSN)
	coreBin := envOrDefault("MODERN_PKI_CORE_BIN", defaultCoreBin)
	outboxCfg, err := loadOutboxConfig()
	if err != nil {
		log.Fatalf("load outbox config: %v", err)
	}

	db, err := sql.Open(dbDriver, dbDSN)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := store.ApplyInitialMigration(context.Background(), db, dbDriver); err != nil {
		log.Fatalf("apply database migration: %v", err)
	}

	repo := store.NewSQLStore(db)
	svc := lifecycle.New(repo, corecli.Runner{Bin: coreBin}, lifecycle.RealClock{}, lifecycle.UUIDGenerator{})
	server := httpapi.New(svc)
	if outboxCfg.Enabled {
		dispatcher := lifecycle.NewOutboxDispatcher(repo, lifecycle.NewLifecycleOutboxHandler(), lifecycle.RealClock{}, lifecycle.UUIDGenerator{})
		worker := lifecycle.NewOutboxWorker(dispatcher, outboxCfg.Interval, outboxCfg.BatchSize, log.Printf)
		go worker.Run(context.Background())
		log.Printf("modern-pki outbox worker enabled interval=%s batch=%d", outboxCfg.Interval, outboxCfg.BatchSize)
	}

	log.Printf("modern-pki service listening on %s", addr)
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("serve HTTP: %v", err)
	}
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func loadOutboxConfig() (outboxConfig, error) {
	enabled, err := parseBoolEnv("MODERN_PKI_OUTBOX_ENABLED", defaultOutboxEnabled)
	if err != nil {
		return outboxConfig{}, err
	}
	interval, err := parseDurationEnv("MODERN_PKI_OUTBOX_INTERVAL", defaultOutboxInterval)
	if err != nil {
		return outboxConfig{}, err
	}
	batchSize, err := parsePositiveIntEnv("MODERN_PKI_OUTBOX_BATCH_SIZE", defaultOutboxBatchSize)
	if err != nil {
		return outboxConfig{}, err
	}
	return outboxConfig{
		Enabled:   enabled,
		Interval:  interval,
		BatchSize: batchSize,
	}, nil
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}

func parseDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func parsePositiveIntEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}
