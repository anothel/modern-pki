package domain

import "errors"

var (
	ErrInvalidRequest             = errors.New("invalid request")
	ErrIdentityNotFound           = errors.New("identity not found")
	ErrIssuerNotFound             = errors.New("issuer not found")
	ErrCertificateProfileNotFound = errors.New("certificate profile not found")
	ErrEnrollmentNotFound         = errors.New("enrollment not found")
	ErrCertificateNotFound        = errors.New("certificate not found")
	ErrInvalidTransition          = errors.New("invalid lifecycle transition")
	ErrCSRParseFailed             = errors.New("csr parse failed")
	ErrCertificateIssuanceFailed  = errors.New("certificate issuance failed")
	ErrStorageFailure             = errors.New("storage failure")
)
