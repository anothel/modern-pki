package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
)

//go:embed migrations/0001_init.sql migrations/0001_init_sqlite.sql
var migrationFiles embed.FS

func ApplyInitialMigration(ctx context.Context, db *sql.DB, driver string) error {
	path, err := initialMigrationPath(driver)
	if err != nil {
		return err
	}

	sqlBytes, err := migrationFiles.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read initial migration: %w", err)
	}

	if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("execute initial migration: %w", err)
	}
	return nil
}

func initialMigrationPath(driver string) (string, error) {
	switch driver {
	case "sqlite":
		return "migrations/0001_init_sqlite.sql", nil
	case "pgx":
		return "migrations/0001_init.sql", nil
	default:
		return "", fmt.Errorf("unsupported database driver %q", driver)
	}
}
