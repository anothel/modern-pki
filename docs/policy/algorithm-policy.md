# Algorithm Policy

## Current Baseline

- SHA-1 issuance is not a supported target.
- Public TLS must follow current CA/Browser Forum Baseline Requirements.
- New weak-algorithm certificates have a target of zero.
- Private key material is outside the service DB/API boundary.

## Required Before Production Expansion

- Profile-level allowed public key algorithms and sizes.
- Profile-level signature algorithms.
- Inventory fields for key algorithm, signature algorithm, provider, and
  relying-party compatibility.
- Migration plan for RSA/ECDSA policy changes.

## PQC Position

PQC and hybrid certificates are lab-only until dependencies, HSM/KMS support,
TLS libraries, ingress, service mesh, and client platforms prove compatibility.

