package corecli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type IssueRequest struct {
	CSRPEM               string    `json:"csr_pem"`
	IssuerCertificatePEM string    `json:"issuer_certificate_pem"`
	IssuerKeyRef         string    `json:"issuer_key_ref"`
	Subject              string    `json:"subject"`
	DNSNames             []string  `json:"dns_names"`
	IPAddresses          []string  `json:"ip_addresses"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	SignatureAlgorithm   string    `json:"signature_algorithm"`
}

type IssueResult struct {
	CertificatePEM string    `json:"certificate_pem"`
	SerialNumber   string    `json:"serial_number"`
	Subject        string    `json:"subject"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

type CSRInfo struct {
	Subject     string   `json:"subject"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
}

type Runner struct {
	Bin string
}

type CommandError struct {
	Code    string
	Message string
	Err     error
}

func (e *CommandError) Error() string {
	const prefix = "modern-pki-core command failed"
	detail := e.Code
	if e.Message != "" {
		if detail != "" {
			detail += ": "
		}
		detail += e.Message
	}
	if detail == "" {
		if e.Err == nil {
			return prefix
		}
		return fmt.Sprintf("%s: %v", prefix, e.Err)
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", prefix, detail)
	}
	return fmt.Sprintf("%s: %s: %v", prefix, detail, e.Err)
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

func (r Runner) InspectCSR(ctx context.Context, csrPEM string) (CSRInfo, error) {
	csrFile, err := os.CreateTemp("", "modern-pki-core-csr-*.pem")
	if err != nil {
		return CSRInfo{}, fmt.Errorf("create csr temp file: %w", err)
	}
	csrPath := csrFile.Name()
	defer os.Remove(csrPath)

	if _, err := csrFile.WriteString(csrPEM); err != nil {
		csrFile.Close()
		return CSRInfo{}, fmt.Errorf("write csr temp file: %w", err)
	}
	if err := csrFile.Close(); err != nil {
		return CSRInfo{}, fmt.Errorf("close csr temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "csr", "inspect", "--in", csrPath, "--out", "json")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return CSRInfo{}, commandError(err, stderr.String())
	}

	var info CSRInfo
	if err := json.NewDecoder(&stdout).Decode(&info); err != nil {
		return CSRInfo{}, fmt.Errorf("decode csr info: %w", err)
	}
	return info, nil
}

func (r Runner) Issue(ctx context.Context, req IssueRequest) (IssueResult, error) {
	requestFile, err := os.CreateTemp("", "modern-pki-core-issue-request-*.json")
	if err != nil {
		return IssueResult{}, fmt.Errorf("create issue request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	if err := json.NewEncoder(requestFile).Encode(req); err != nil {
		requestFile.Close()
		return IssueResult{}, fmt.Errorf("write issue request: %w", err)
	}
	if err := requestFile.Close(); err != nil {
		return IssueResult{}, fmt.Errorf("close issue request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "modern-pki-core-issue-result-*.json")
	if err != nil {
		return IssueResult{}, fmt.Errorf("create issue result temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)

	if err := resultFile.Close(); err != nil {
		return IssueResult{}, fmt.Errorf("close issue result temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "cert", "issue", "--request", requestPath, "--out", resultPath)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return IssueResult{}, commandError(err, stderr.String())
	}

	resultFile, err = os.Open(resultPath)
	if err != nil {
		return IssueResult{}, fmt.Errorf("open issue result: %w", err)
	}
	defer resultFile.Close()

	var result IssueResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return IssueResult{}, fmt.Errorf("decode issue result: %w", err)
	}
	return result, nil
}

type commandErrorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func commandError(err error, stderr string) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return &CommandError{Err: err}
	}

	var payload commandErrorPayload
	if json.Unmarshal([]byte(stderr), &payload) == nil && (payload.Code != "" || payload.Message != "") {
		return &CommandError{Code: payload.Code, Message: payload.Message, Err: err}
	}

	return &CommandError{Message: stderr, Err: err}
}
