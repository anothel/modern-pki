package main

import (
	"strings"
	"testing"
	"time"

	"github.com/modern-pki/modern-pki/service/internal/httpapi"
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

func TestLoadAuthConfigDefaults(t *testing.T) {
	clearAuthEnv(t)

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if cfg.HTTP.Mode != httpapi.AuthModeDev || cfg.BootstrapAPIKey != "" {
		t.Fatalf("auth config = %#v, want dev mode without bootstrap key", cfg)
	}
}

func TestLoadAuthConfigAPIKeyMode(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("MODERN_PKI_AUTH_MODE", "api_key")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY", "bootstrap-token")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY_NAME", "bootstrap-admin")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR", "ops-admin")

	cfg, err := loadAuthConfig()
	if err != nil {
		t.Fatalf("loadAuthConfig returned error: %v", err)
	}
	if cfg.HTTP.Mode != httpapi.AuthModeAPIKey ||
		cfg.BootstrapAPIKey != "bootstrap-token" ||
		cfg.BootstrapAPIKeyName != "bootstrap-admin" ||
		cfg.BootstrapAPIKeyActor != "ops-admin" {
		t.Fatalf("auth config = %#v", cfg)
	}
}

func TestLoadAuthConfigRejectsInvalidMode(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("MODERN_PKI_AUTH_MODE", "mtls")

	_, err := loadAuthConfig()
	if err == nil || !strings.Contains(err.Error(), "MODERN_PKI_AUTH_MODE") {
		t.Fatalf("loadAuthConfig error = %v, want MODERN_PKI_AUTH_MODE", err)
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

func TestLoadACMEHTTP01VerifierConfigDefaults(t *testing.T) {
	t.Setenv("MODERN_PKI_ACME_HTTP01_BASE_URL", "")

	cfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		t.Fatalf("loadACMEHTTP01VerifierConfig returned error: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Fatalf("base URL = %q, want empty", cfg.BaseURL)
	}
}

func TestLoadACMEHTTP01VerifierConfigCustomBaseURL(t *testing.T) {
	t.Setenv("MODERN_PKI_ACME_HTTP01_BASE_URL", "http://127.0.0.1:5002")

	cfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		t.Fatalf("loadACMEHTTP01VerifierConfig returned error: %v", err)
	}
	if cfg.BaseURL != "http://127.0.0.1:5002" {
		t.Fatalf("base URL = %q", cfg.BaseURL)
	}
}

func TestLoadACMEHTTP01VerifierConfigRejectsInvalidBaseURL(t *testing.T) {
	t.Setenv("MODERN_PKI_ACME_HTTP01_BASE_URL", "://bad-url")

	_, err := loadACMEHTTP01VerifierConfig()
	if err == nil || !strings.Contains(err.Error(), "MODERN_PKI_ACME_HTTP01_BASE_URL") {
		t.Fatalf("loadACMEHTTP01VerifierConfig error = %v, want MODERN_PKI_ACME_HTTP01_BASE_URL", err)
	}
}

func clearExpirationScanEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_ENABLED", "")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_INTERVAL", "")
	t.Setenv("MODERN_PKI_EXPIRATION_WARNING_WINDOW", "")
	t.Setenv("MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE", "")
}

func clearAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MODERN_PKI_AUTH_MODE", "")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY", "")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY_NAME", "")
	t.Setenv("MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR", "")
}
