package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"

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
)

func main() {
	addr := envOrDefault("MODERN_PKI_ADDR", defaultAddr)
	dbDriver := envOrDefault("MODERN_PKI_DB_DRIVER", defaultDBDriver)
	dbDSN := envOrDefault("MODERN_PKI_DB_DSN", defaultDBDSN)
	coreBin := envOrDefault("MODERN_PKI_CORE_BIN", defaultCoreBin)

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
