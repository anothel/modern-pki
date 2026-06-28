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
	CSRPEM                     string    `json:"csr_pem"`
	IssuerCertificatePEM       string    `json:"issuer_certificate_pem"`
	IssuerKeyRef               string    `json:"issuer_key_ref"`
	AIAURL                     string    `json:"aia_url,omitempty"`
	CRLDistributionPoints      []string  `json:"crl_distribution_points,omitempty"`
	Subject                    string    `json:"subject"`
	DNSNames                   []string  `json:"dns_names"`
	IPAddresses                []string  `json:"ip_addresses"`
	NotBefore                  time.Time `json:"not_before"`
	NotAfter                   time.Time `json:"not_after"`
	SignatureAlgorithm         string    `json:"signature_algorithm"`
	ProfileID                  string    `json:"profile_id,omitempty"`
	BasicConstraintsCritical   bool      `json:"basic_constraints_critical,omitempty"`
	BasicConstraintsCA         bool      `json:"basic_constraints_ca,omitempty"`
	BasicConstraintsMaxPathLen *int      `json:"basic_constraints_max_path_len,omitempty"`
	KeyUsageCritical           bool      `json:"key_usage_critical,omitempty"`
	KeyUsage                   []string  `json:"key_usage,omitempty"`
	ExtendedKeyUsageCritical   bool      `json:"extended_key_usage_critical,omitempty"`
	ExtendedKeyUsage           []string  `json:"extended_key_usage,omitempty"`
	SubjectKeyIdentifier       bool      `json:"subject_key_identifier,omitempty"`
	AuthorityKeyIdentifier     bool      `json:"authority_key_identifier,omitempty"`
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

type RevokedCertificate struct {
	SerialNumber string
	RevokedAt    time.Time
	Reason       string
}

type GenerateCRLRequest struct {
	IssuerCertificatePEM string
	IssuerKeyRef         string
	CRLNumber            int64
	ThisUpdate           time.Time
	NextUpdate           time.Time
	RevokedCertificates  []RevokedCertificate
}

type GenerateCRLResult struct {
	CRLPEM string `json:"crl_pem"`
}

type OCSPCertificateID struct {
	SerialNumber   string `json:"serial_number"`
	IssuerNameHash string `json:"issuer_name_hash"`
	IssuerKeyHash  string `json:"issuer_key_hash"`
	HashAlgorithm  string `json:"hash_algorithm"`
}

type OCSPRequestInfo struct {
	Certificates []OCSPCertificateID `json:"certificates"`
	HasNonce     bool                `json:"has_nonce"`
	NonceHex     string              `json:"nonce_hex"`
}

type OCSPIssuerInfo struct {
	IssuerNameHash string `json:"issuer_name_hash"`
	IssuerKeyHash  string `json:"issuer_key_hash"`
	HashAlgorithm  string `json:"hash_algorithm"`
}

type ValidateOCSPResponderResult struct {
	Valid bool `json:"valid"`
}

type OCSPCertificateStatus struct {
	SerialNumber     string
	Status           string
	RevokedAt        time.Time
	RevocationReason string
	HashAlgorithm    string
	IssuerNameHash   string
	IssuerKeyHash    string
}

type GenerateOCSPResponseRequest struct {
	RequestDER           []byte
	IssuerCertificatePEM string
	IssuerKeyRef         string
	ThisUpdate           time.Time
	NextUpdate           time.Time
	Certificates         []OCSPCertificateStatus
}

type GenerateOCSPResponseResult struct {
	ResponseDER []byte
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

func (r Runner) GenerateCRL(ctx context.Context, req GenerateCRLRequest) (GenerateCRLResult, error) {
	requestFile, err := os.CreateTemp("", "modern-pki-core-crl-request-*.json")
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("create crl request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	fileReq := crlFileRequest{
		IssuerCertificatePEM: req.IssuerCertificatePEM,
		IssuerKeyRef:         req.IssuerKeyRef,
		CRLNumber:            req.CRLNumber,
		ThisUpdate:           coreTime(req.ThisUpdate),
		NextUpdate:           coreTime(req.NextUpdate),
		RevokedSerialNumbers: make([]string, 0, len(req.RevokedCertificates)),
		RevokedAtTimes:       make([]string, 0, len(req.RevokedCertificates)),
		RevocationReasons:    make([]string, 0, len(req.RevokedCertificates)),
	}
	for _, revoked := range req.RevokedCertificates {
		fileReq.RevokedSerialNumbers = append(fileReq.RevokedSerialNumbers, revoked.SerialNumber)
		fileReq.RevokedAtTimes = append(fileReq.RevokedAtTimes, coreTime(revoked.RevokedAt))
		fileReq.RevocationReasons = append(fileReq.RevocationReasons, revoked.Reason)
	}
	if err := json.NewEncoder(requestFile).Encode(fileReq); err != nil {
		requestFile.Close()
		return GenerateCRLResult{}, fmt.Errorf("write crl request: %w", err)
	}
	if err := requestFile.Close(); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("close crl request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "modern-pki-core-crl-result-*.json")
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("create crl result temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)

	if err := resultFile.Close(); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("close crl result temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "crl", "generate", "--request", requestPath, "--out", resultPath)
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return GenerateCRLResult{}, commandError(err, stderr.String())
	}

	resultFile, err = os.Open(resultPath)
	if err != nil {
		return GenerateCRLResult{}, fmt.Errorf("open crl result: %w", err)
	}
	defer resultFile.Close()

	var result GenerateCRLResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return GenerateCRLResult{}, fmt.Errorf("decode crl result: %w", err)
	}
	return result, nil
}

func (r Runner) InspectOCSP(ctx context.Context, requestDER []byte) (OCSPRequestInfo, error) {
	requestFile, err := os.CreateTemp("", "modern-pki-core-ocsp-request-*.der")
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("create ocsp request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	if _, err := requestFile.Write(requestDER); err != nil {
		requestFile.Close()
		return OCSPRequestInfo{}, fmt.Errorf("write ocsp request: %w", err)
	}
	if err := requestFile.Close(); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("close ocsp request: %w", err)
	}

	resultFile, err := os.CreateTemp("", "modern-pki-core-ocsp-info-*.json")
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("create ocsp info temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("close ocsp info temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "ocsp", "inspect", "--in", requestPath, "--out", resultPath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return OCSPRequestInfo{}, commandError(err, stderr.String())
	}

	resultFile, err = os.Open(resultPath)
	if err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("open ocsp info: %w", err)
	}
	defer resultFile.Close()

	var result OCSPRequestInfo
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return OCSPRequestInfo{}, fmt.Errorf("decode ocsp info: %w", err)
	}
	return result, nil
}

func (r Runner) InspectOCSPIssuer(ctx context.Context, issuerCertificatePEM string, hashAlgorithm string) (OCSPIssuerInfo, error) {
	issuerFile, err := os.CreateTemp("", "modern-pki-core-ocsp-issuer-*.pem")
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("create ocsp issuer temp file: %w", err)
	}
	issuerPath := issuerFile.Name()
	defer os.Remove(issuerPath)

	if _, err := issuerFile.WriteString(issuerCertificatePEM); err != nil {
		issuerFile.Close()
		return OCSPIssuerInfo{}, fmt.Errorf("write ocsp issuer: %w", err)
	}
	if err := issuerFile.Close(); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("close ocsp issuer: %w", err)
	}

	resultFile, err := os.CreateTemp("", "modern-pki-core-ocsp-issuer-info-*.json")
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("create ocsp issuer info temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("close ocsp issuer info temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	if hashAlgorithm == "" {
		hashAlgorithm = "sha1"
	}
	cmd := exec.CommandContext(ctx, bin, "ocsp", "inspect-issuer", "--issuer", issuerPath, "--out", resultPath, "--hash", hashAlgorithm)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return OCSPIssuerInfo{}, commandError(err, stderr.String())
	}

	resultFile, err = os.Open(resultPath)
	if err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("open ocsp issuer info: %w", err)
	}
	defer resultFile.Close()

	var result OCSPIssuerInfo
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return OCSPIssuerInfo{}, fmt.Errorf("decode ocsp issuer info: %w", err)
	}
	return result, nil
}

func (r Runner) ValidateOCSPResponder(ctx context.Context, issuerCertificatePEM string, responderCertificatePEM string) (ValidateOCSPResponderResult, error) {
	issuerFile, err := os.CreateTemp("", "modern-pki-core-ocsp-issuer-*.pem")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp issuer temp file: %w", err)
	}
	issuerPath := issuerFile.Name()
	defer os.Remove(issuerPath)
	if _, err := issuerFile.WriteString(issuerCertificatePEM); err != nil {
		issuerFile.Close()
		return ValidateOCSPResponderResult{}, fmt.Errorf("write ocsp issuer: %w", err)
	}
	if err := issuerFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp issuer: %w", err)
	}

	responderFile, err := os.CreateTemp("", "modern-pki-core-ocsp-responder-*.pem")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp responder temp file: %w", err)
	}
	responderPath := responderFile.Name()
	defer os.Remove(responderPath)
	if _, err := responderFile.WriteString(responderCertificatePEM); err != nil {
		responderFile.Close()
		return ValidateOCSPResponderResult{}, fmt.Errorf("write ocsp responder: %w", err)
	}
	if err := responderFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp responder: %w", err)
	}

	resultFile, err := os.CreateTemp("", "modern-pki-core-ocsp-responder-validation-*.json")
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("create ocsp responder validation temp file: %w", err)
	}
	resultPath := resultFile.Name()
	defer os.Remove(resultPath)
	if err := resultFile.Close(); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("close ocsp responder validation temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "ocsp", "validate-responder", "--issuer", issuerPath, "--responder", responderPath, "--out", resultPath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return ValidateOCSPResponderResult{}, commandError(err, stderr.String())
	}

	resultFile, err = os.Open(resultPath)
	if err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("open ocsp responder validation: %w", err)
	}
	defer resultFile.Close()

	var result ValidateOCSPResponderResult
	if err := json.NewDecoder(resultFile).Decode(&result); err != nil {
		return ValidateOCSPResponderResult{}, fmt.Errorf("decode ocsp responder validation: %w", err)
	}
	return result, nil
}

func (r Runner) GenerateOCSPResponse(ctx context.Context, req GenerateOCSPResponseRequest) (GenerateOCSPResponseResult, error) {
	requestDERFile, err := os.CreateTemp("", "modern-pki-core-ocsp-request-*.der")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp request temp file: %w", err)
	}
	requestDERPath := requestDERFile.Name()
	defer os.Remove(requestDERPath)
	if _, err := requestDERFile.Write(req.RequestDER); err != nil {
		requestDERFile.Close()
		return GenerateOCSPResponseResult{}, fmt.Errorf("write ocsp request der: %w", err)
	}
	if err := requestDERFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp request der: %w", err)
	}

	requestFile, err := os.CreateTemp("", "modern-pki-core-ocsp-response-request-*.json")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp response request temp file: %w", err)
	}
	requestPath := requestFile.Name()
	defer os.Remove(requestPath)

	fileReq := ocspResponseFileRequest{
		IssuerCertificatePEM: req.IssuerCertificatePEM,
		IssuerKeyRef:         req.IssuerKeyRef,
		ThisUpdate:           coreTime(req.ThisUpdate),
		NextUpdate:           coreTime(req.NextUpdate),
		SerialNumbers:        make([]string, 0, len(req.Certificates)),
		HashAlgorithms:       make([]string, 0, len(req.Certificates)),
		IssuerNameHashes:     make([]string, 0, len(req.Certificates)),
		IssuerKeyHashes:      make([]string, 0, len(req.Certificates)),
		Statuses:             make([]string, 0, len(req.Certificates)),
		RevokedAtTimes:       make([]string, 0, len(req.Certificates)),
		RevocationReasons:    make([]string, 0, len(req.Certificates)),
	}
	for _, certificate := range req.Certificates {
		fileReq.SerialNumbers = append(fileReq.SerialNumbers, certificate.SerialNumber)
		fileReq.HashAlgorithms = append(fileReq.HashAlgorithms, certificate.HashAlgorithm)
		fileReq.IssuerNameHashes = append(fileReq.IssuerNameHashes, certificate.IssuerNameHash)
		fileReq.IssuerKeyHashes = append(fileReq.IssuerKeyHashes, certificate.IssuerKeyHash)
		fileReq.Statuses = append(fileReq.Statuses, certificate.Status)
		fileReq.RevokedAtTimes = append(fileReq.RevokedAtTimes, coreTime(certificate.RevokedAt))
		fileReq.RevocationReasons = append(fileReq.RevocationReasons, certificate.RevocationReason)
	}
	if err := json.NewEncoder(requestFile).Encode(fileReq); err != nil {
		requestFile.Close()
		return GenerateOCSPResponseResult{}, fmt.Errorf("write ocsp response request: %w", err)
	}
	if err := requestFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp response request: %w", err)
	}

	responseFile, err := os.CreateTemp("", "modern-pki-core-ocsp-response-*.der")
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("create ocsp response temp file: %w", err)
	}
	responsePath := responseFile.Name()
	defer os.Remove(responsePath)
	if err := responseFile.Close(); err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("close ocsp response temp file: %w", err)
	}

	bin := r.Bin
	if bin == "" {
		bin = "modern-pki-core"
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "ocsp", "respond", "--in", requestDERPath, "--request", requestPath, "--out", responsePath)
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return GenerateOCSPResponseResult{}, commandError(err, stderr.String())
	}

	responseDER, err := os.ReadFile(responsePath)
	if err != nil {
		return GenerateOCSPResponseResult{}, fmt.Errorf("read ocsp response: %w", err)
	}
	return GenerateOCSPResponseResult{ResponseDER: responseDER}, nil
}

type crlFileRequest struct {
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
	IssuerKeyRef         string   `json:"issuer_key_ref"`
	CRLNumber            int64    `json:"crl_number"`
	ThisUpdate           string   `json:"this_update"`
	NextUpdate           string   `json:"next_update"`
	RevokedSerialNumbers []string `json:"revoked_serial_numbers"`
	RevokedAtTimes       []string `json:"revoked_at_times"`
	RevocationReasons    []string `json:"revocation_reasons"`
}

type ocspResponseFileRequest struct {
	IssuerCertificatePEM string   `json:"issuer_certificate_pem"`
	IssuerKeyRef         string   `json:"issuer_key_ref"`
	ThisUpdate           string   `json:"this_update"`
	NextUpdate           string   `json:"next_update"`
	SerialNumbers        []string `json:"serial_numbers"`
	HashAlgorithms       []string `json:"hash_algorithms"`
	IssuerNameHashes     []string `json:"issuer_name_hashes"`
	IssuerKeyHashes      []string `json:"issuer_key_hashes"`
	Statuses             []string `json:"statuses"`
	RevokedAtTimes       []string `json:"revoked_at_times"`
	RevocationReasons    []string `json:"revocation_reasons"`
}

func coreTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
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
