package store

import (
	"context"

	"github.com/modern-pki/modern-pki/service/internal/domain"
)

type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity domain.Identity) error
	GetIdentity(ctx context.Context, id string) (domain.Identity, error)
	ListIdentities(ctx context.Context) ([]domain.Identity, error)
}

type IssuerRepository interface {
	CreateIssuer(ctx context.Context, issuer domain.Issuer) error
	GetIssuer(ctx context.Context, id string) (domain.Issuer, error)
}

type CertificateProfileRepository interface {
	CreateCertificateProfile(ctx context.Context, profile domain.CertificateProfile) error
	GetCertificateProfile(ctx context.Context, id string) (domain.CertificateProfile, error)
	ListCertificateProfiles(ctx context.Context) ([]domain.CertificateProfile, error)
}

type EnrollmentRepository interface {
	CreateEnrollment(ctx context.Context, enrollment domain.Enrollment) error
	GetEnrollment(ctx context.Context, id string) (domain.Enrollment, error)
	ListEnrollments(ctx context.Context) ([]domain.Enrollment, error)
	UpdateEnrollment(ctx context.Context, enrollment domain.Enrollment) error
	UpdateEnrollmentIfStatus(ctx context.Context, enrollment domain.Enrollment, currentStatus domain.EnrollmentStatus) error
}

type CertificateRepository interface {
	CreateCertificate(ctx context.Context, certificate domain.Certificate) error
	GetCertificate(ctx context.Context, id string) (domain.Certificate, error)
	ListCertificates(ctx context.Context) ([]domain.Certificate, error)
	UpdateCertificate(ctx context.Context, certificate domain.Certificate) error
	UpdateCertificateIfStatus(ctx context.Context, certificate domain.Certificate, currentStatus domain.CertificateStatus) error
}

type RevocationRepository interface {
	CreateRevocation(ctx context.Context, revocation domain.Revocation) error
}

type AuditRepository interface {
	CreateAuditEvent(ctx context.Context, event domain.AuditEvent) error
	ListAuditEvents(ctx context.Context) ([]domain.AuditEvent, error)
}

type Repository interface {
	IdentityRepository
	IssuerRepository
	CertificateProfileRepository
	EnrollmentRepository
	CertificateRepository
	RevocationRepository
	AuditRepository
	WithinTx(ctx context.Context, fn func(Repository) error) error
}
