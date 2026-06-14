package domain

import "time"

type IdentityType string

const (
	IdentityUser      IdentityType = "user"
	IdentityMachine   IdentityType = "machine"
	IdentityService   IdentityType = "service"
	IdentityIoTDevice IdentityType = "iot_device"
	IdentityWorkload  IdentityType = "workload"
)

type IdentityStatus string

const (
	IdentityActive   IdentityStatus = "active"
	IdentityDisabled IdentityStatus = "disabled"
)

type IssuerStatus string

const (
	IssuerActive   IssuerStatus = "active"
	IssuerDisabled IssuerStatus = "disabled"
)

type EnrollmentStatus string

const (
	EnrollmentPending  EnrollmentStatus = "pending"
	EnrollmentApproved EnrollmentStatus = "approved"
	EnrollmentRejected EnrollmentStatus = "rejected"
	EnrollmentIssued   EnrollmentStatus = "issued"
	EnrollmentCanceled EnrollmentStatus = "canceled"
)

type CertificateStatus string

const (
	CertificateValid     CertificateStatus = "valid"
	CertificateSuspended CertificateStatus = "suspended"
	CertificateRevoked   CertificateStatus = "revoked"
	CertificateExpired   CertificateStatus = "expired"
)

type CRLPublicationStatus string

const (
	CRLPublicationPublished CRLPublicationStatus = "published"
)

type RevocationReason string

const (
	RevocationKeyCompromise        RevocationReason = "key_compromise"
	RevocationCACompromise         RevocationReason = "ca_compromise"
	RevocationAffiliationChanged   RevocationReason = "affiliation_changed"
	RevocationSuperseded           RevocationReason = "superseded"
	RevocationCessationOfOperation RevocationReason = "cessation_of_operation"
	RevocationPrivilegeWithdrawn   RevocationReason = "privilege_withdrawn"
	RevocationUnspecified          RevocationReason = "unspecified"
)

type IssuerKind string

const (
	IssuerRootCA         IssuerKind = "root_ca"
	IssuerIntermediateCA IssuerKind = "intermediate_ca"
)

type Identity struct {
	ID         string
	Type       IdentityType
	Name       string
	ExternalID string
	Status     IdentityStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type Issuer struct {
	ID             string
	Name           string
	Kind           IssuerKind
	Status         IssuerStatus
	CertificatePEM string
	KeyRef         string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type StringListExtensionPolicy struct {
	Critical bool     `json:"critical"`
	Values   []string `json:"values"`
}

type BasicConstraintsPolicy struct {
	Critical   bool `json:"critical"`
	CA         bool `json:"ca"`
	MaxPathLen *int `json:"max_path_len,omitempty"`
}

type CertificateProfile struct {
	ID                     string
	Name                   string
	Description            string
	IssuerID               string
	ValidityPeriodSeconds  int64
	SubjectTemplate        string
	AllowedDNSPatterns     []string
	AllowedIPRanges        []string
	KeyUsage               StringListExtensionPolicy
	ExtendedKeyUsage       StringListExtensionPolicy
	BasicConstraints       BasicConstraintsPolicy
	SubjectKeyIdentifier   bool
	AuthorityKeyIdentifier bool
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type Enrollment struct {
	ID                   string
	IdentityID           string
	IssuerID             string
	CertificateProfileID string
	CSRPEM               string
	Status               EnrollmentStatus
	RequestedSubject     string
	RequestedDNSNames    []string
	RequestedIPAddresses []string
	CSRDNSNames          []string
	CSRIPAddresses       []string
	RequestedNotAfter    time.Time
	ApprovedBy           string
	ApprovedAt           time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type Certificate struct {
	ID                   string
	IdentityID           string
	IssuerID             string
	EnrollmentID         string
	CertificateProfileID string
	SerialNumber         string
	Subject              string
	DNSNames             []string
	IPAddresses          []string
	NotBefore            time.Time
	NotAfter             time.Time
	Status               CertificateStatus
	CertificatePEM       string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type Revocation struct {
	ID            string
	CertificateID string
	Reason        RevocationReason
	RevokedBy     string
	RevokedAt     time.Time
	CreatedAt     time.Time
}

type RevokedCertificateEntry struct {
	CertificateID string
	SerialNumber  string
	RevokedAt     time.Time
	Reason        RevocationReason
}

type CRLPublication struct {
	ID                string
	IssuerID          string
	DistributionPoint string
	CRLNumber         int64
	ThisUpdate        time.Time
	NextUpdate        time.Time
	Status            CRLPublicationStatus
	CRLPEM            string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type AuditEvent struct {
	ID           string
	Actor        string
	Action       string
	ResourceType string
	ResourceID   string
	MetadataJSON string
	CreatedAt    time.Time
}
