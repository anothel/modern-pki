package corecli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRunnerMapsIssueResultJSON(t *testing.T) {
	bin := writeFakeIssueCommand(t, true)

	result, err := (Runner{Bin: bin}).Issue(context.Background(), IssueRequest{
		CSRPEM:               "csr-pem",
		IssuerCertificatePEM: "issuer-pem",
		IssuerKeyRef:         "issuer-key-ref",
		Subject:              "CN=leaf",
		DNSNames:             []string{"leaf.example.test"},
		IPAddresses:          []string{"127.0.0.1"},
		NotBefore:            time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:             time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC),
		SignatureAlgorithm:   "ECDSA-SHA256",
	})
	if err != nil {
		t.Fatalf("Issue returned error: %v", err)
	}

	if result.CertificatePEM != "cert-pem" {
		t.Fatalf("CertificatePEM = %q, want %q", result.CertificatePEM, "cert-pem")
	}
	if result.SerialNumber != "12345" {
		t.Fatalf("SerialNumber = %q, want %q", result.SerialNumber, "12345")
	}
	if result.Subject != "CN=leaf" {
		t.Fatalf("Subject = %q, want %q", result.Subject, "CN=leaf")
	}
	if !result.NotBefore.Equal(time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("NotBefore = %s", result.NotBefore.Format(time.RFC3339))
	}
	if !result.NotAfter.Equal(time.Date(2026, time.January, 3, 4, 5, 6, 0, time.UTC)) {
		t.Fatalf("NotAfter = %s", result.NotAfter.Format(time.RFC3339))
	}
}

func TestRunnerMapsCommandFailure(t *testing.T) {
	bin := writeFakeIssueCommand(t, false)

	_, err := (Runner{Bin: bin}).Issue(context.Background(), IssueRequest{
		CSRPEM: "csr-pem",
	})
	if err == nil {
		t.Fatal("Issue returned nil error")
	}

	for _, want := range []string{"CORE_ISSUE_FAILED", "bad csr"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

func TestRunnerMapsCSRInfoJSON(t *testing.T) {
	bin := writeFakeInspectCommand(t, true)

	info, err := (Runner{Bin: bin}).InspectCSR(context.Background(), "csr-pem")
	if err != nil {
		t.Fatalf("InspectCSR returned error: %v", err)
	}

	if info.Subject != "CN=leaf" {
		t.Fatalf("Subject = %q, want CN=leaf", info.Subject)
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != "leaf.example.test" || info.DNSNames[1] != "alt.example.test" {
		t.Fatalf("DNSNames = %#v", info.DNSNames)
	}
	if len(info.IPAddresses) != 1 || info.IPAddresses[0] != "127.0.0.1" {
		t.Fatalf("IPAddresses = %#v", info.IPAddresses)
	}
}

func TestRunnerMapsCSRInspectFailure(t *testing.T) {
	bin := writeFakeInspectCommand(t, false)

	_, err := (Runner{Bin: bin}).InspectCSR(context.Background(), "bad-csr")
	if err == nil {
		t.Fatal("InspectCSR returned nil error")
	}

	for _, want := range []string{"csr.pem_read_failed", "bad csr"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to contain %q", err.Error(), want)
		}
	}
}

func TestRunnerGenerateCRLNormalizesTimes(t *testing.T) {
	capturePath := filepath.Join(t.TempDir(), "crl-request.json")
	bin := writeFakeCRLCommand(t, true, capturePath)

	result, err := (Runner{Bin: bin}).GenerateCRL(context.Background(), GenerateCRLRequest{
		IssuerCertificatePEM: "issuer-pem",
		IssuerKeyRef:         "issuer-key-ref",
		CRLNumber:            7,
		ThisUpdate:           time.Date(2026, time.January, 2, 3, 4, 5, 123456789, time.FixedZone("KST", 9*60*60)),
		NextUpdate:           time.Date(2026, time.January, 3, 4, 5, 6, 987654321, time.UTC),
		RevokedCertificates: []RevokedCertificate{{
			SerialNumber: "12345",
			RevokedAt:    time.Date(2026, time.January, 2, 4, 4, 5, 999999999, time.FixedZone("KST", 9*60*60)),
			Reason:       "key_compromise",
		}},
	})
	if err != nil {
		t.Fatalf("GenerateCRL returned error: %v", err)
	}
	if result.CRLPEM != "crl-pem" {
		t.Fatalf("CRLPEM = %q, want crl-pem", result.CRLPEM)
	}

	payload, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatalf("read captured request: %v", err)
	}
	body := string(payload)
	for _, want := range []string{
		`"this_update":"2026-01-01T18:04:05Z"`,
		`"next_update":"2026-01-03T04:05:06Z"`,
		`"revoked_at_times":["2026-01-01T19:04:05Z"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("captured request = %s, want it to contain %s", body, want)
		}
	}
	if strings.Contains(body, ".123") || strings.Contains(body, ".987") || strings.Contains(body, ".999") {
		t.Fatalf("captured request contains fractional seconds: %s", body)
	}
}

func TestRunnerMapsOCSPIssuerInfoJSON(t *testing.T) {
	bin := writeFakeOCSPIssuerInspectCommand(t, true)

	info, err := (Runner{Bin: bin}).InspectOCSPIssuer(context.Background(), "issuer-pem")
	if err != nil {
		t.Fatalf("InspectOCSPIssuer returned error: %v", err)
	}

	if info.IssuerNameHash != "name-hash" {
		t.Fatalf("IssuerNameHash = %q, want name-hash", info.IssuerNameHash)
	}
	if info.IssuerKeyHash != "key-hash" {
		t.Fatalf("IssuerKeyHash = %q, want key-hash", info.IssuerKeyHash)
	}
}

func TestCommandErrorPreservesPayloadCode(t *testing.T) {
	err := commandError(errors.New("exit status 1"), `{"code":"issue.csr_parse_failed","message":"bad csr"}`)

	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("error type = %T, want *CommandError", err)
	}
	if commandErr.Code != "issue.csr_parse_failed" {
		t.Fatalf("command error code = %q, want issue.csr_parse_failed", commandErr.Code)
	}
	if commandErr.Message != "bad csr" {
		t.Fatalf("command error message = %q, want bad csr", commandErr.Message)
	}
}

func writeFakeInspectCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "modern-pki-core.bat")
		if err := os.WriteFile(path, []byte(windowsInspectScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "modern-pki-core")
	if err := os.WriteFile(path, []byte(unixInspectScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeIssueCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "modern-pki-core.bat")
		if err := os.WriteFile(path, []byte(windowsIssueScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "modern-pki-core")
	if err := os.WriteFile(path, []byte(unixIssueScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeCRLCommand(t *testing.T, success bool, capturePath string) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "modern-pki-core.bat")
		if err := os.WriteFile(path, []byte(windowsCRLScript(success, capturePath)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "modern-pki-core")
	if err := os.WriteFile(path, []byte(unixCRLScript(success, capturePath)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func writeFakeOCSPIssuerInspectCommand(t *testing.T, success bool) string {
	t.Helper()

	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		path := filepath.Join(dir, "modern-pki-core.bat")
		if err := os.WriteFile(path, []byte(windowsOCSPIssuerInspectScript(success)), 0644); err != nil {
			t.Fatalf("write fake command: %v", err)
		}
		return path
	}

	path := filepath.Join(dir, "modern-pki-core")
	if err := os.WriteFile(path, []byte(unixOCSPIssuerInspectScript(success)), 0755); err != nil {
		t.Fatalf("write fake command: %v", err)
	}
	return path
}

func windowsIssueScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"CORE_ISSUE_FAILED^\",^\"message^\":^\"bad csr^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%OUT%\"==\"\" exit /b 2",
		"> \"%OUT%\" echo {^\"certificate_pem^\":^\"cert-pem^\",^\"serial_number^\":^\"12345^\",^\"subject^\":^\"CN=leaf^\",^\"not_before^\":^\"2026-01-02T03:04:05Z^\",^\"not_after^\":^\"2026-01-03T04:05:06Z^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsCRLScript(success bool, capturePath string) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"crl.create_failed^\",^\"message^\":^\"bad crl request^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"REQ=\"",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--request\" (",
		"  set \"REQ=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%REQ%\"==\"\" exit /b 2",
		"if \"%OUT%\"==\"\" exit /b 2",
		"copy /Y \"%REQ%\" \"" + capturePath + "\" >NUL",
		"> \"%OUT%\" echo {^\"crl_pem^\":^\"crl-pem^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsOCSPIssuerInspectScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"ocsp.issuer_parse_failed^\",^\"message^\":^\"bad issuer^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"setlocal",
		"set \"OUT=\"",
		":loop",
		"if \"%~1\"==\"\" goto done",
		"if \"%~1\"==\"--out\" (",
		"  set \"OUT=%~2\"",
		"  shift",
		"  shift",
		"  goto loop",
		")",
		"shift",
		"goto loop",
		":done",
		"if \"%OUT%\"==\"\" exit /b 2",
		"> \"%OUT%\" echo {^\"issuer_name_hash^\":^\"name-hash^\",^\"issuer_key_hash^\":^\"key-hash^\"}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func windowsInspectScript(success bool) string {
	if !success {
		return strings.Join([]string{
			"@echo off",
			"echo {^\"code^\":^\"csr.pem_read_failed^\",^\"message^\":^\"bad csr^\"} 1>&2",
			"exit /b 7",
			"",
		}, "\r\n")
	}

	return strings.Join([]string{
		"@echo off",
		"echo {^\"subject^\":^\"CN=leaf^\",^\"dns_names^\": [^\"leaf.example.test^\", ^\"alt.example.test^\"],^\"ip_addresses^\": [^\"127.0.0.1^\"]}",
		"exit /b 0",
		"",
	}, "\r\n")
}

func unixIssueScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"CORE_ISSUE_FAILED","message":"bad csr"}' >&2
exit 7
`
	}

	return `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$out" ]; then
	exit 2
fi
cat > "$out" <<'JSON'
{"certificate_pem":"cert-pem","serial_number":"12345","subject":"CN=leaf","not_before":"2026-01-02T03:04:05Z","not_after":"2026-01-03T04:05:06Z"}
JSON
exit 0
`
}

func unixCRLScript(success bool, capturePath string) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"crl.create_failed","message":"bad crl request"}' >&2
exit 7
`
	}

	escapedCapturePath := strings.ReplaceAll(capturePath, "'", "'\"'\"'")
	return `#!/bin/sh
req=""
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--request" ]; then
		req="$2"
		shift 2
	elif [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$req" ] || [ -z "$out" ]; then
	exit 2
fi
cp "$req" '` + escapedCapturePath + `'
cat > "$out" <<'JSON'
{"crl_pem":"crl-pem"}
JSON
exit 0
`
}

func unixOCSPIssuerInspectScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"ocsp.issuer_parse_failed","message":"bad issuer"}' >&2
exit 7
`
	}

	return `#!/bin/sh
out=""
while [ "$#" -gt 0 ]; do
	if [ "$1" = "--out" ]; then
		out="$2"
		shift 2
	else
		shift
	fi
done
if [ -z "$out" ]; then
	exit 2
fi
cat > "$out" <<'JSON'
{"issuer_name_hash":"name-hash","issuer_key_hash":"key-hash"}
JSON
exit 0
`
}

func unixInspectScript(success bool) string {
	if !success {
		return `#!/bin/sh
printf '%s\n' '{"code":"csr.pem_read_failed","message":"bad csr"}' >&2
exit 7
`
	}

	return `#!/bin/sh
printf '%s\n' '{"subject":"CN=leaf","dns_names":["leaf.example.test","alt.example.test"],"ip_addresses":["127.0.0.1"]}'
exit 0
`
}
