# Threat Model

## Assets

- issuer and responder key references
- certificate inventory
- identities and owner metadata
- enrollment approvals
- revocation state
- audit events
- ACME account/order/challenge state

## Main Threats

| Threat | Control now | Gap |
| --- | --- | --- |
| Mis-issuance | Profile policy, identity allow-lists, approval flow, ACME validation. | More negative profile tests and cert linting. |
| Key exposure | `key_ref`, no DB private key material, production docs. | HSM/KMS/PKCS#11 provider and ceremony evidence. |
| Privilege abuse | API key scopes, audit metadata. | RBAC/ABAC and break-glass workflow. |
| Replay/duplicate issuance | Issuance attempts and ACME nonce handling. | More multi-node smoke coverage. |
| Status outage | CRL/OCSP backed by service state. | HA deployment drills. |
| Supply chain compromise | CI builds/tests. | SAST/SCA/SBOM/secret/container/IaC scans and release signing. |

## Review Triggers

- new key provider
- new discovery/import source
- new deployment adapter
- public TLS integration change
- new algorithm policy

