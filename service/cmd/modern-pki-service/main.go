package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

	defaultExpirationScanEnabled       = false
	defaultExpirationScanInterval      = time.Hour
	defaultExpirationScanWarningWindow = 30 * 24 * time.Hour
	defaultExpirationScanBatchSize     = 100

	defaultBootstrapAPIKeyName  = "bootstrap"
	defaultBootstrapAPIKeyActor = "bootstrap"

	defaultACMESmokeValidity     = 24 * time.Hour
	defaultACMESmokeIssuerKeyRef = ".tmp/acme-smoke/acme-smoke-issuer.key"

	productionEnv                   = "production"
	minProductionBootstrapKeyLength = 32
	defaultServiceVersion           = "dev"
	defaultServiceCommit            = "unknown"
	defaultServiceBuildTime         = "unknown"
	defaultShutdownTimeout          = 10 * time.Second
)

var (
	serviceVersion   = defaultServiceVersion
	serviceCommit    = defaultServiceCommit
	serviceBuildTime = defaultServiceBuildTime
)

type outboxConfig struct {
	Enabled   bool
	Interval  time.Duration
	BatchSize int
}

type expirationScanConfig struct {
	Enabled       bool
	Interval      time.Duration
	WarningWindow time.Duration
	BatchSize     int
}

type acmeHTTP01VerifierConfig struct {
	BaseURL string
}

type acmeDefaultsConfig struct {
	BootstrapDefaults bool
	ValidityPeriod    time.Duration
	IssuerKeyRef      string
}

type authConfig struct {
	HTTP                 httpapi.AuthConfig
	BootstrapAPIKey      string
	BootstrapAPIKeyName  string
	BootstrapAPIKeyActor string
	APIKeyPepper         string
}

type operationalConfig struct {
	Version   string
	Commit    string
	BuildTime string
	StartedAt time.Time
	Ready     func(context.Context) error
}

func main() {
	startedAt := time.Now().UTC()
	rootCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	addr := envOrDefault("MODERN_PKI_ADDR", defaultAddr)
	dbDriver := envOrDefault("MODERN_PKI_DB_DRIVER", defaultDBDriver)
	dbDSN := envOrDefault("MODERN_PKI_DB_DSN", defaultDBDSN)
	coreBin := envOrDefault("MODERN_PKI_CORE_BIN", defaultCoreBin)
	authCfg, err := loadAuthConfig()
	if err != nil {
		log.Fatalf("load auth config: %v", err)
	}
	outboxCfg, err := loadOutboxConfig()
	if err != nil {
		log.Fatalf("load outbox config: %v", err)
	}
	expirationScanCfg, err := loadExpirationScanConfig()
	if err != nil {
		log.Fatalf("load expiration scan config: %v", err)
	}
	acmeHTTP01VerifierCfg, err := loadACMEHTTP01VerifierConfig()
	if err != nil {
		log.Fatalf("load ACME HTTP-01 verifier config: %v", err)
	}
	acmeDefaultsCfg, err := loadACMEDefaultsConfig()
	if err != nil {
		log.Fatalf("load ACME defaults config: %v", err)
	}

	db, err := sql.Open(dbDriver, dbDSN)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	if err := store.ApplyInitialMigration(rootCtx, db, dbDriver); err != nil {
		log.Fatalf("apply database migration: %v", err)
	}

	repo := store.NewSQLStore(db)
	acmeHTTP01Verifier, err := lifecycle.NewACMEHTTP01Verifier(acmeHTTP01VerifierCfg.BaseURL)
	if err != nil {
		log.Fatalf("create ACME HTTP-01 verifier: %v", err)
	}
	svc := lifecycle.NewWithACMEHTTP01VerifierAndAPIKeyPepper(repo, corecli.Runner{Bin: coreBin}, lifecycle.RealClock{}, lifecycle.UUIDGenerator{}, acmeHTTP01Verifier, authCfg.APIKeyPepper)
	if isProductionEnv(os.Getenv("MODERN_PKI_ENV")) {
		svc.EnableProductionPolicy()
	}
	if acmeHTTP01VerifierCfg.BaseURL != "" {
		log.Printf("modern-pki ACME HTTP-01 verifier override enabled base_url=%s", acmeHTTP01VerifierCfg.BaseURL)
	}
	if authCfg.BootstrapAPIKey != "" {
		key, err := svc.EnsureAPIKey(rootCtx, "system", lifecycle.EnsureAPIKeyRequest{
			Name:  authCfg.BootstrapAPIKeyName,
			Token: authCfg.BootstrapAPIKey,
			Actor: authCfg.BootstrapAPIKeyActor,
		})
		if err != nil {
			log.Fatalf("bootstrap api key: %v", err)
		}
		log.Printf("modern-pki bootstrap api key ready id=%s name=%s actor=%s", key.ID, key.Name, key.Actor)
	}
	acmeHTTPConfig := httpapi.ACMEConfig{}
	if acmeDefaultsCfg.BootstrapDefaults {
		acmeHTTPConfig, err = bootstrapACMEDefaults(rootCtx, svc, acmeDefaultsCfg.ValidityPeriod, acmeDefaultsCfg.IssuerKeyRef)
		if err != nil {
			log.Fatalf("bootstrap ACME defaults: %v", err)
		}
		log.Printf("modern-pki ACME defaults ready identity_id=%s issuer_id=%s profile_id=%s validity=%s", acmeHTTPConfig.DefaultIdentityID, acmeHTTPConfig.DefaultIssuerID, acmeHTTPConfig.DefaultCertificateProfileID, acmeHTTPConfig.DefaultValidityPeriod)
	}
	server := httpapi.NewWithAuthAndACME(svc, authCfg.HTTP, acmeHTTPConfig)
	if outboxCfg.Enabled {
		webhookHandler := lifecycle.NewWebhookOutboxHandler(repo, nil)
		dispatcher := lifecycle.NewOutboxDispatcher(repo, lifecycle.NewLifecycleOutboxHandlerWithWebhook(webhookHandler), lifecycle.RealClock{}, lifecycle.UUIDGenerator{})
		worker := lifecycle.NewOutboxWorker(dispatcher, outboxCfg.Interval, outboxCfg.BatchSize, log.Printf)
		go worker.Run(rootCtx)
		log.Printf("modern-pki outbox worker enabled interval=%s batch=%d", outboxCfg.Interval, outboxCfg.BatchSize)
	}
	if expirationScanCfg.Enabled {
		worker := lifecycle.NewExpirationScanWorker(svc, expirationScanCfg.Interval, expirationScanCfg.WarningWindow, expirationScanCfg.BatchSize, log.Printf)
		go worker.Run(rootCtx)
		log.Printf("modern-pki expiration scan worker enabled interval=%s warning_window=%s batch=%d", expirationScanCfg.Interval, expirationScanCfg.WarningWindow, expirationScanCfg.BatchSize)
	}
	handler := newOperationalHandler(server, operationalConfig{
		Version:   serviceVersion,
		Commit:    serviceCommit,
		BuildTime: serviceBuildTime,
		StartedAt: startedAt,
		Ready:     newDatabaseReadinessCheck(db, dbDriver),
	})

	log.Printf("modern-pki service listening on %s", addr)
	httpServer := newHTTPServer(addr, handler)
	if err := runServerUntilShutdown(rootCtx, httpServer.ListenAndServe, httpServer.Shutdown, defaultShutdownTimeout, log.Printf); err != nil {
		log.Fatalf("serve HTTP: %v", err)
	}
}

func newDatabaseReadinessCheck(db *sql.DB, driver string) func(context.Context) error {
	return func(ctx context.Context) error {
		readyCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if err := db.PingContext(readyCtx); err != nil {
			return err
		}
		return store.CheckInitialMigration(readyCtx, db, driver)
	}
}

func runServerUntilShutdown(ctx context.Context, serve func() error, shutdown func(context.Context) error, timeout time.Duration, logf func(string, ...any)) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		if logf != nil {
			logf("modern-pki service shutting down")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			return err
		}
		select {
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-shutdownCtx.Done():
			return shutdownCtx.Err()
		}
	}
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

func newOperationalHandler(next http.Handler, cfg operationalConfig) http.Handler {
	if cfg.Version == "" {
		cfg.Version = defaultServiceVersion
	}
	if cfg.Commit == "" {
		cfg.Commit = defaultServiceCommit
	}
	if cfg.BuildTime == "" {
		cfg.BuildTime = defaultServiceBuildTime
	}
	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = time.Now().UTC()
	}
	if cfg.Ready == nil {
		cfg.Ready = func(context.Context) error { return nil }
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"status":     "ok",
			"started_at": cfg.StartedAt.Format(time.RFC3339Nano),
		})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.Ready(r.Context()) != nil {
			writeOperationalJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not_ready",
				"error":  "readiness check failed",
			})
			return
		}
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
		})
	})
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		writeOperationalJSON(w, http.StatusOK, map[string]any{
			"service":    "modern-pki-service",
			"version":    cfg.Version,
			"commit":     cfg.Commit,
			"build_time": cfg.BuildTime,
		})
	})
	mux.Handle("/", next)
	return mux
}

func writeOperationalJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func loadAuthConfig() (authConfig, error) {
	modeValue := strings.TrimSpace(envOrDefault("MODERN_PKI_AUTH_MODE", string(httpapi.AuthModeDev)))
	mode := httpapi.AuthMode(modeValue)
	switch mode {
	case httpapi.AuthModeDev, httpapi.AuthModeAPIKey:
	default:
		return authConfig{}, fmt.Errorf("MODERN_PKI_AUTH_MODE must be %q or %q", httpapi.AuthModeDev, httpapi.AuthModeAPIKey)
	}

	bootstrapAPIKey := os.Getenv("MODERN_PKI_BOOTSTRAP_API_KEY")
	apiKeyPepper := os.Getenv("MODERN_PKI_API_KEY_PEPPER")
	trustedProxies, err := parseTrustedProxiesEnv("MODERN_PKI_TRUSTED_PROXIES")
	if err != nil {
		return authConfig{}, err
	}
	if err := validateProductionAuthConfig(os.Getenv("MODERN_PKI_ENV"), mode, bootstrapAPIKey, apiKeyPepper); err != nil {
		return authConfig{}, err
	}

	return authConfig{
		HTTP: httpapi.AuthConfig{
			Mode:           mode,
			TrustedProxies: trustedProxies,
		},
		BootstrapAPIKey:      bootstrapAPIKey,
		BootstrapAPIKeyName:  envOrDefault("MODERN_PKI_BOOTSTRAP_API_KEY_NAME", defaultBootstrapAPIKeyName),
		BootstrapAPIKeyActor: envOrDefault("MODERN_PKI_BOOTSTRAP_API_KEY_ACTOR", defaultBootstrapAPIKeyActor),
		APIKeyPepper:         strings.TrimSpace(apiKeyPepper),
	}, nil
}

func parseTrustedProxiesEnv(name string) ([]netip.Prefix, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	values := strings.Split(raw, ",")
	proxies := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := parseTrustedProxy(value)
		if err != nil {
			return nil, fmt.Errorf("%s contains invalid proxy %q: %w", name, value, err)
		}
		proxies = append(proxies, prefix)
	}
	return proxies, nil
}

func parseTrustedProxy(value string) (netip.Prefix, error) {
	if strings.Contains(value, "/") {
		return netip.ParsePrefix(value)
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func validateProductionAuthConfig(env string, mode httpapi.AuthMode, bootstrapAPIKey string, apiKeyPepper string) error {
	if !isProductionEnv(env) {
		return nil
	}
	if mode == httpapi.AuthModeDev {
		return fmt.Errorf("MODERN_PKI_ENV=%s requires MODERN_PKI_AUTH_MODE=%q", productionEnv, httpapi.AuthModeAPIKey)
	}
	if isWeakProductionSecret(apiKeyPepper) {
		return fmt.Errorf("MODERN_PKI_API_KEY_PEPPER must be at least %d characters and not a common default in production", minProductionBootstrapKeyLength)
	}
	if bootstrapAPIKey != "" && isWeakProductionBootstrapAPIKey(bootstrapAPIKey) {
		return fmt.Errorf("MODERN_PKI_BOOTSTRAP_API_KEY must be at least %d characters and not a common default in production", minProductionBootstrapKeyLength)
	}
	return nil
}

func isProductionEnv(env string) bool {
	return strings.EqualFold(strings.TrimSpace(env), productionEnv)
}

func isWeakProductionBootstrapAPIKey(token string) bool {
	return isWeakProductionSecret(token)
}

func isWeakProductionSecret(token string) bool {
	trimmed := strings.TrimSpace(token)
	if len(trimmed) < minProductionBootstrapKeyLength {
		return true
	}
	if isSingleRepeatedRune(trimmed) {
		return true
	}
	switch strings.ToLower(trimmed) {
	case "change-me", "changeme", "bootstrap", "bootstrap-token", "password", "secret", "admin", "modern-pki", "modern-pki-bootstrap":
		return true
	default:
		return false
	}
}

func isSingleRepeatedRune(value string) bool {
	var first rune
	for idx, current := range value {
		if idx == 0 {
			first = current
			continue
		}
		if current != first {
			return false
		}
	}
	return value != ""
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

func loadExpirationScanConfig() (expirationScanConfig, error) {
	enabled, err := parseBoolEnv("MODERN_PKI_EXPIRATION_SCAN_ENABLED", defaultExpirationScanEnabled)
	if err != nil {
		return expirationScanConfig{}, err
	}
	interval, err := parseDurationEnv("MODERN_PKI_EXPIRATION_SCAN_INTERVAL", defaultExpirationScanInterval)
	if err != nil {
		return expirationScanConfig{}, err
	}
	warningWindow, err := parseNonNegativeDurationEnv("MODERN_PKI_EXPIRATION_WARNING_WINDOW", defaultExpirationScanWarningWindow)
	if err != nil {
		return expirationScanConfig{}, err
	}
	batchSize, err := parsePositiveIntEnv("MODERN_PKI_EXPIRATION_SCAN_BATCH_SIZE", defaultExpirationScanBatchSize)
	if err != nil {
		return expirationScanConfig{}, err
	}
	return expirationScanConfig{
		Enabled:       enabled,
		Interval:      interval,
		WarningWindow: warningWindow,
		BatchSize:     batchSize,
	}, nil
}

func loadACMEHTTP01VerifierConfig() (acmeHTTP01VerifierConfig, error) {
	baseURL := strings.TrimSpace(os.Getenv("MODERN_PKI_ACME_HTTP01_BASE_URL"))
	if baseURL != "" {
		if _, err := lifecycle.NewACMEHTTP01Verifier(baseURL); err != nil {
			return acmeHTTP01VerifierConfig{}, fmt.Errorf("MODERN_PKI_ACME_HTTP01_BASE_URL: %w", err)
		}
	}
	return acmeHTTP01VerifierConfig{BaseURL: baseURL}, nil
}

func loadACMEDefaultsConfig() (acmeDefaultsConfig, error) {
	bootstrap, err := parseBoolEnv("MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS", false)
	if err != nil {
		return acmeDefaultsConfig{}, err
	}
	validity, err := parseDurationEnv("MODERN_PKI_ACME_DEFAULT_VALIDITY", defaultACMESmokeValidity)
	if err != nil {
		return acmeDefaultsConfig{}, err
	}
	return acmeDefaultsConfig{
		BootstrapDefaults: bootstrap,
		ValidityPeriod:    validity,
		IssuerKeyRef:      envOrDefault("MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF", defaultACMESmokeIssuerKeyRef),
	}, nil
}

func bootstrapACMEDefaults(ctx context.Context, svc *lifecycle.Service, validity time.Duration, issuerKeyRef string) (httpapi.ACMEConfig, error) {
	issuerCertificatePEM, issuerKeyRef, err := ensureACMESmokeIssuerMaterial(issuerKeyRef)
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	identity, err := svc.CreateIdentity(ctx, "system", lifecycle.CreateIdentityRequest{
		Type:       "machine",
		Name:       "acme-smoke-edge-01",
		ExternalID: "acme-smoke-edge-01",
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	issuer, err := svc.CreateIssuer(ctx, "system", lifecycle.CreateIssuerRequest{
		Name:           "acme-smoke-issuer",
		Kind:           "intermediate_ca",
		CertificatePEM: issuerCertificatePEM,
		KeyRef:         issuerKeyRef,
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	profile, err := svc.CreateCertificateProfile(ctx, "system", lifecycle.CreateCertificateProfileRequest{
		IssuerID:              issuer.ID,
		Name:                  "acme-smoke-profile",
		ValidityPeriodSeconds: int64(validity.Seconds()),
		AllowedDNSPatterns:    []string{"*.example.test"},
		AllowedIPRanges:       []string{"127.0.0.0/8"},
	})
	if err != nil {
		return httpapi.ACMEConfig{}, err
	}
	return httpapi.ACMEConfig{
		DefaultIdentityID:           identity.ID,
		DefaultIssuerID:             issuer.ID,
		DefaultCertificateProfileID: profile.ID,
		DefaultValidityPeriod:       validity,
	}, nil
}

func ensureACMESmokeIssuerMaterial(issuerKeyRef string) (string, string, error) {
	if strings.TrimSpace(issuerKeyRef) == "" {
		return "", "", fmt.Errorf("MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF must not be empty")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate ACME smoke issuer key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return "", "", fmt.Errorf("generate ACME smoke issuer serial: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "modern-pki ACME Smoke CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", fmt.Errorf("create ACME smoke issuer certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal ACME smoke issuer key: %w", err)
	}
	keyDir := filepath.Dir(issuerKeyRef)
	if keyDir != "." {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return "", "", fmt.Errorf("create ACME smoke issuer key dir: %w", err)
		}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(issuerKeyRef, keyPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write ACME smoke issuer key: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return certPEM, issuerKeyRef, nil
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

func parseNonNegativeDurationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	if parsed < 0 {
		return 0, fmt.Errorf("%s must be non-negative", name)
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
