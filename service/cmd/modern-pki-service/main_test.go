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

func TestLoadExpirationScanConfigDefaults(t *testing.T) {
	clearExpirationScanEnv(t)

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if cfg.Enabled || cfg.Interval != time.Hour || cfg.WarningWindow != 30*24*time.Hour || cfg.BatchSize != 100 {
		t.Fatalf("config = %#v, want disabled 1h warning 720h batch 100", cfg)
	}
}

func TestLoadExpirationScanConfigCustomValues(t *testing.T) {
	clearExpirationScanEnv(t)
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_ENABLED", "true")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_INTERVAL", "15m")
	t.Setenv("MODERN_PKI_EXPIRATION_WARNING_WINDOW", "168h")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE", "50")

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if !cfg.Enabled || cfg.Interval != 15*time.Minute || cfg.WarningWindow != 168*time.Hour || cfg.BatchSize != 50 {
		t.Fatalf("config = %#v, want enabled 15m warning 168h batch 50", cfg)
	}
}

func TestLoadExpirationScanConfigAllowsZeroWarningWindow(t *testing.T) {
	clearExpirationScanEnv(t)
	t.Setenv("MODERN_PKI_EXPIRATION_WARNING_WINDOW", "0s")

	cfg, err := loadExpirationScanConfig()
	if err != nil {
		t.Fatalf("loadExpirationScanConfig returned error: %v", err)
	}
	if cfg.WarningWindow != 0 {
		t.Fatalf("warning window = %s, want 0", cfg.WarningWindow)
	}
}

func TestLoadExpirationScanConfigRejectsInvalidValues(t *testing.T) {
	for _, tt := range []struct {
		name      string
		envName   string
		envValue  string
		wantError string
	}{
		{name: "enabled", envName: "MODERN_PKI_EXPIRATION_SCAN_ENABLED", envValue: "sometimes", wantError: "MODERN_PKI_EXPIRATION_SCAN_ENABLED"},
		{name: "interval", envName: "MODERN_PKI_EXPIRATION_SCAN_INTERVAL", envValue: "0s", wantError: "MODERN_PKI_EXPIRATION_SCAN_INTERVAL"},
		{name: "warning window", envName: "MODERN_PKI_EXPIRATION_WARNING_WINDOW", envValue: "-1h", wantError: "MODERN_PKI_EXPIRATION_WARNING_WINDOW"},
		{name: "batch", envName: "MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE", envValue: "0", wantError: "MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			clearExpirationScanEnv(t)
			t.Setenv(tt.envName, tt.envValue)

			_, err := loadExpirationScanConfig()
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("loadExpirationScanConfig error = %v, want mention %s", err, tt.wantError)
			}
		})
	}
}

func clearExpirationScanEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_ENABLED", "")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_INTERVAL", "")
	t.Setenv("MODERN_PKI_EXPIRATION_WARNING_WINDOW", "")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE", "")
}
