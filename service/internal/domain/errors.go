package domain

import "errors"

var (
	ErrInvalidRequest                = errors.New("invalid request")
	ErrUnsupportedMediaType          = errors.New("unsupported media type")
	ErrUnauthorized                  = errors.New("unauthorized")
	ErrForbidden                     = errors.New("forbidden")
	ErrIdentityNotFound              = errors.New("identity not found")
	ErrIssuerNotFound                = errors.New("issuer not found")
	ErrOCSPResponderNotFound         = errors.New("ocsp responder not found")
	ErrNotificationEndpointNotFound  = errors.New("notification endpoint not found")
	ErrCertificateProfileNotFound    = errors.New("certificate profile not found")
	ErrEnrollmentNotFound            = errors.New("enrollment not found")
	ErrCertificateNotFound           = errors.New("certificate not found")
	ErrCRLPublicationNotFound        = errors.New("crl publication not found")
	ErrOutboxMessageNotFound         = errors.New("outbox message not found")
	ErrAPIKeyNotFound                = errors.New("api key not found")
	ErrInvalidTransition             = errors.New("invalid lifecycle transition")
	ErrCSRParseFailed                = errors.New("csr parse failed")
	ErrCertificateIssuanceFailed     = errors.New("certificate issuance failed")
	ErrCRLGenerationFailed           = errors.New("crl generation failed")
	ErrOCSPDecodeFailed              = errors.New("ocsp decode failed")
	ErrOCSPResponseFailed            = errors.New("ocsp response failed")
	ErrOCSPResponderValidationFailed = errors.New("ocsp responder validation failed")
	ErrStorageFailure                = errors.New("storage failure")
)
