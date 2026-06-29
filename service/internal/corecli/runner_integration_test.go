package corecli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCoreCLIIntegrationCommandErrors(t *testing.T) {
	bin := strings.TrimSpace(os.Getenv("MODERN_PKI_CORE_BIN"))
	if bin == "" {
		t.Skip("set MODERN_PKI_CORE_BIN to run core CLI boundary integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runner := Runner{Bin: bin}

	tests := []struct {
		name string
		run  func() error
		code string
	}{
		{
			name: "csr inspect",
			run: func() error {
				_, err := runner.InspectCSR(ctx, "not a csr")
				return err
			},
			code: "csr.parse_failed",
		},
		{
			name: "ocsp inspect",
			run: func() error {
				_, err := runner.InspectOCSP(ctx, []byte("not an ocsp request"))
				return err
			},
			code: "ocsp.parse_failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("command returned nil error")
			}
			var commandErr *CommandError
			if !errors.As(err, &commandErr) {
				t.Fatalf("error type = %T, want *CommandError", err)
			}
			if commandErr.Code != tt.code {
				t.Fatalf("command error code = %q, want %q", commandErr.Code, tt.code)
			}
			if commandErr.Message == "" {
				t.Fatal("command error message is empty")
			}
		})
	}
}
