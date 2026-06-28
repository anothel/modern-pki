# Improvement Analysis Alignment

This file maps the uploaded 2026-06-27 improvement analysis to current repo
evidence and future-only gaps. It prevents the external analysis from becoming
a parallel roadmap.

## P0 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Code and doc baseline | README, SECURITY, CONTRIBUTING, CI, OpenAPI, runbooks, compliance matrix, this alignment file, docs validator. | Keep docs validation in CI and update this file when major architecture changes land. |
| Certificate inventory | Identity ownership metadata, certificate inventory API, expiry SLO, list filters, SQL indexes. | First real discovery/import source still deferred until operators choose it. |
| Shorter certificate lifetime | Expiration scan, expiry SLO, public TLS 200/100/47-day ceilings, ACME HTTP-01 flow. | Deployment adapters and full automated deployment/reload checks remain future work. |
| Certificate profiles | Profile-as-code fields for validity, Basic Constraints, KU, EKU, SAN, SKI, AKI. | Add profile-level key/signature algorithm policy and issued DER golden tests. |
| Key protection | `key_ref` model, production docs require external key provider, DB excludes private key material. | HSM/KMS/PKCS#11 provider boundary, ceremony evidence, and non-exportable-key audit behavior remain future work. |
| Audit log | Structured audit metadata, request context, API key fingerprint, query, retention, repair path. | Tamper-evident storage and SIEM export examples remain future work. |
| Documentation | Architecture, policy, operations, security, ADR, runbook, compliance docs now have baseline files. | Keep detailed procedures current with implementation changes. |

## P1 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Issuance validation | Identity SAN allow-lists, public TLS CAA/DNSSEC/RFC 8657 checks, HTTP-01 ACME validation. | DNS-01 and EAB wait for real integrations; tls-alpn-01 is not selected. |
| Access control | API key auth, scopes, bootstrap runbook, audit metadata. | Human RBAC/ABAC and approval workflows remain future work. |
| Revocation/status service | Revocation API, CRL publication, OCSP endpoint, public TLS mass-revocation checklist. | HA deployment validation and scheduled tabletop evidence remain future work. |
| Observability | Structured logs, expvar metrics, operation metrics, readiness checks, observability reference. | Exporter/backend integration, synthetic checks, CT monitoring remain future work. |
| DevSecOps | CI builds/tests Go, C++, PostgreSQL migration integration, docs validation, high-confidence secret baseline scan. | Full SAST/SCA/SBOM/container/IaC scans and release signing remain future work. |

## P2/P3 Areas

| Analysis area | Current repo evidence | Remaining gap |
| --- | --- | --- |
| Crypto agility and PQC | Project scope and roadmap keep production PQC deferred; profile policy exists. | Crypto inventory, algorithm migration plan, PQC readiness, and vendor tracking remain future work. |
| Repository structure | Current repo uses `docs/reference` and `docs/runbooks` plus new architecture/policy/operations/security/ADR baselines. | Do not reshuffle files only to match the analysis tree; links and validation carry the contract. |
