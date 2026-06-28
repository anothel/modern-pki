# Certificate Profile Policy

Certificate profiles are policy-as-code. They must define issuance limits before
signing happens.

## Enforced Today

- Validity ceiling through `validity_period_seconds`.
- Public TLS validity ceilings for 200/100/47-day eras.
- Basic Constraints.
- Key Usage.
- Extended Key Usage.
- Subject Alternative Name DNS/IP patterns.
- Subject Key Identifier and Authority Key Identifier settings.
- Public TLS CAA DNSSEC and RFC 8657 parameter checks.
- Issued DER assertions for SAN, KU, EKU, Basic Constraints, AIA, CRL
  Distribution Points, SKI, and AKI.

## Required Review For New Profiles

- Intended usage: serverAuth, clientAuth, internal mTLS, device, public TLS, or
  future code signing.
- Allowed DNS and IP namespace.
- Wildcard allowance.
- Public TLS flag and validation evidence requirement.
- Expiration window and renewal margin.

## Gaps

- Profile-level key algorithm policy.
- Profile-level signature algorithm policy.
