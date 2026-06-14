package main

import (
	"strings"
	"testing"
	"time"
)

func TestLoadOutboxConfigDefaults(t *testing.T) {
	t.Setenv("MODERN_PKI_OUTBOX_ENABLED", "")
	t.Setenv("MODERN_PKI_OUTBOX_INTERVAL", "")
	t.Setenv("MODERN_PKI_OUTBOX_BATCH_SIZE", "")

	cfg, err := loadOutboxConfig()
	if err != nil {
		t.Fatalf("loadOutboxConfig returned error: %v", err)
	}
	if !cfg.Enabled || cfg.Interval != 5*time.Second || cfg.BatchSize != 10 {
		t.Fatalf("config = %#v, want enabled 5s batch 10", cfg)
	}
}

func TestLoadOutboxConfigCustomValues(t *testing.T) {
	t.Setenv("MODERN_PKI_OUTBOX_ENABLED", "false")
	t.Setenv("MODERN_PKI_OUTBOX_INTERVAL", "30s")
	t.Setenv("MODERN_PKI_OUTBOX_BATCH_SIZE", "25")

	cfg, err := loadOutboxConfig()
	if err != nil {
		t.Fatalf("loadOutboxConfig returned error: %v", err)
	}
	if cfg.Enabled || cfg.Interval != 30*time.Second || cfg.BatchSize != 25 {
		t.Fatalf("config = %#v, want disabled 30s batch 25", cfg)
	}
}

func TestLoadOutboxConfigRejectsInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		envName   string
		envValue  string
		wantError string
	}{
		{name: "enabled", envName: "MODERN_PKI_OUTBOX_ENABLED", envValue: "sometimes", wantError: "MODERN_PKI_OUTBOX_ENABLED"},
		{name: "interval", envName: "MODERN_PKI_OUTBOX_INTERVAL", envValue: "0s", wantError: "MODERN_PKI_OUTBOX_INTERVAL"},
		{name: "batch", envName: "MODERN_PKI_OUTBOX_BATCH_SIZE", envValue: "0", wantError: "MODERN_PKI_OUTBOX_BATCH_SIZE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MODERN_PKI_OUTBOX_ENABLED", "")
			t.Setenv("MODERN_PKI_OUTBOX_INTERVAL", "")
			t.Setenv("MODERN_PKI_OUTBOX_BATCH_SIZE", "")
			t.Setenv(tt.envName, tt.envValue)

			_, err := loadOutboxConfig()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("loadOutboxConfig error = %v, want mention %s", err, tt.wantError)
			}
		})
	}
}
