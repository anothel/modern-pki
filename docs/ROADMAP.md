# modern-pki roadmap

Only future work belongs here. Completed items must be removed after the
verification evidence is recorded in the relevant reference or runbook.

This roadmap folds in the uploaded PKI improvement analyses, including the
2026-06-28 repository analysis. Those documents are inputs, not parallel
backlogs. Current execution guidance lives in
[Release readiness action plan](reference/release-readiness-action-plan.md).

## Operating Rules

- Prefer reliability, parity checks, and negative tests before feature surface.
- Keep work grouped by risk area; do not stop at tiny slices when one coherent
  risk area can be closed.
- Do not split large files only because they are large. Add contract and
  failure-mode coverage first, then split along repeated change boundaries.
- Keep discovery, deploy adapters, EAB, DNS-01, UI, and PQC gated on real
  operator demand.
- Reject new abstractions until two real implementations exist or current code
  blocks a concrete requirement.
- Reject new dependencies unless stdlib/native code is materially worse or the
  dependency is a selected release/security tool.

## External Timeline Drivers

Publicly trusted TLS work must track the CA/Browser Forum Baseline
Requirements. As of BR 2.2.8, public Subscriber Certificate validity and
Domain/IP validation reuse shrink on this schedule. Source:
https://cabforum.org/working-groups/server/baseline-requirements/requirements/

| Date | Public TLS max validity | Domain/IP validation reuse |
| --- | ---: | ---: |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | 47 days | 10 days |

Private PKI is not forced to follow public Web PKI timelines, but the same
timeline is a useful pressure test: manual renewal and deployment must disappear
before 100-day and 47-day public certificate operations become normal.

## P1: ACME Client Compatibility

Goal: convert real-client differences into stable protocol fixtures.

- Run certbot smoke from Linux or elevated Windows.
- If certbot smoke exposes client-specific behavior differences, convert them
  into protocol fixture tests.
- Keep the ACME compatibility matrix current by client, OS, account key type,
  challenge type, and result.
- Add External Account Binding only after a real subscriber/account integration
  requires it.
- Add DNS-01 only after an operator-owned DNS provider integration is selected.

## P1: CSR And Certificate Correctness

Goal: prevent malformed, weak, or policy-violating certificates at approval and
signing boundaries.

- Add CSR linting for key algorithm, key size, malformed PEM, forbidden
  extensions, SAN/CN policy, wildcard policy, IP SAN policy, and oversized SAN
  lists.
- Add profile-level key algorithm policy.
- Add profile-level signature algorithm policy.
- Add negative tests for CN-only requests, missing SAN, invalid EKU/KU
  combinations, weak keys, expired chains, name constraints, malformed PEM,
  duplicate serials, and oversized SAN lists.
- Add public TLS linting hook before issuance only if public TLS issuance is
  enabled.

## P1: Release Operations

Goal: make pre-1.0 release candidates repeatable.

- Add release artifact/SBOM/signing decision and implementation.
- Add dependency/SAST scan selection and CI wiring.
- Add optional `go test -race ./...`, `go vet ./...`, staticcheck, gosec, C++
  sanitizer, and fuzz jobs after tool choices are accepted.
- Add binary/package distribution decision.
- Add compatibility matrix for OS, Go, OpenSSL, SQLite, PostgreSQL, lego, and
  certbot.
- Add generated API example validation if example drift becomes visible.

## P2: Key Boundary

Goal: separate local file-key development from production signing semantics.

- Select HSM/KMS/PKCS#11 provider semantics for issuer and OCSP responder
  signing.
- Separate file key provider from production signing providers in code.
- Add API and audit behavior for non-exportable keys.
- Add executable key ceremony evidence capture and intermediate rollover drill.
- Add offline-root operating model if this project owns CA hierarchy operations.
- Add audit tests proving key material is never recorded.
- Add PKCS#11 mock or software-token test path.

## P2: Audit, Access, And Operations

Goal: raise operator accountability and recovery confidence.

- Add append-only or tamper-evident audit storage plan.
- Add SIEM export format and detection examples for issuance, revocation,
  policy change, key-provider use, and CA operations.
- Add human RBAC/ABAC roles for requester, approver, operator, auditor, and
  break-glass actions.
- Add approval reason, policy decision reason, validation evidence ref,
  old/new serial on renewal, and deployment target audit fields where source
  data exists.
- Add synthetic checks for CRL, OCSP, ACME order/finalize, and post-deployment
  certificate health after a deployment target is selected.
- Add issuer key rotation, intermediate rollover, CRL/OCSP outage, audit repair,
  webhook dead-letter, migration rollback, and restore drill evidence updates
  to runbooks as implementations change.

## P2: Inventory And Discovery

Goal: prove one import model before broad scanning.

- Keep discovery/import scoped to the first real source requested by operators.
- Add owner-missing and 30/60/90-day expiry exception reports once the first
  real import source exists.
- Move any remaining service-side inventory filtering into SQL only when large
  inventory tests show response time risk.

## P3: Maintainability And Core Robustness

Goal: reduce review risk after correctness coverage exists.

- Define JSON schema for Go-to-core CLI calls.
- Add contract tests for the Go/C++ boundary.
- Expose structured OpenSSL error details where useful for operator diagnosis.
- Add CSR, OCSP, and CRL parser fuzz targets with local commands.
- Split `service/internal/httpapi/server.go` only along stable boundaries such
  as ACME, API key/auth, audit/outbox/webhook, and operator/reporting handlers.
- Split `service/internal/store/sqlstore.go` only along aggregate boundaries
  such as certificate, audit, outbox, ACME nonce, and migration behavior.

## P4: Product Expansion

- Add certificate rotation automation that includes deploy target update,
  post-deploy health check, rollback, and operator notification.
- Add deploy adapters only after an operator picks concrete first targets;
  likely first targets are Kubernetes Secret and load balancer.
- Add Kubernetes workload identity.
- Add CT or external certificate monitoring for public DNS names.
- Add crypto inventory for TLS, mTLS, JWT/JWS, S/MIME, code signing, SSH,
  database encryption, and backup encryption.
- Add crypto agility registry for key algorithm, signature algorithm, provider,
  and profile compatibility.
- Add algorithm migration plan and 47-day renewal/retry/load simulation report.
- Add PQC/hybrid experiments with clear non-production labeling.
- Track HSM, KMS, TLS library, service mesh, ingress, load balancer, and client
  PQC readiness before any production PQC/hybrid rollout.
- Add UI only after operator API shape and filters stabilize.

## SLO And KPI Targets

| Measure | Target |
| --- | ---: |
| Inventory coverage | 90% first pass, 99% after stabilization |
| Owner assignment | 100% for newly managed certificates |
| Automated renewal coverage | 70% first pass, 95% for public/critical certs |
| Certificates unhandled inside 14-day expiry window | 0 |
| Renewal success rate | 99%+ |
| Revocation request traceability | 100% |
| Missing audit events for issue/renew/revoke/policy change | 0 |
| New weak-algorithm certificates | 0 |
| OCSP/CRL freshness violations | 0 |
| Policy-violating issuance | 0 |

## Defer Or Delete

- Defer broad discovery scanners until one concrete source proves inventory
  fields and ownership workflow.
- Defer deploy adapters beyond the first selected target.
- Defer UI until API filters, pagination, and operator flows stabilize.
- Defer PQC from production; keep lab-only until dependencies and relying-party
  support are real.
- Defer EAB and DNS-01 until real integrations require them.
- Reject large file splitting until tests prove behavior and repeated changes
  prove a stable boundary.
- Reject new product surface while release trust, contract parity, failure-mode
  coverage, key-boundary, and recovery evidence remain incomplete.
