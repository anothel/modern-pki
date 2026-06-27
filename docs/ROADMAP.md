# modern-pki roadmap

Only future work belongs here.

This roadmap folds in the uploaded PKI improvement analysis, but keeps the file
future-only: already implemented lifecycle APIs, profile policy, CRL/OCSP
basics, audit metadata, outbox/webhooks, expiration scans, and ACME adapter
foundations are not repeated as new work.

## External Timeline Drivers

Publicly trusted TLS work must track the CA/Browser Forum Baseline Requirements.
As of BR 2.2.8, public Subscriber Certificate validity and Domain/IP validation
reuse shrink on this schedule. Source:
https://cabforum.org/working-groups/server/baseline-requirements/requirements/

| Date | Public TLS max validity | Domain/IP validation reuse |
| --- | ---: | ---: |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | 47 days | 10 days |

Private PKI is not forced to follow public Web PKI timelines, but the same
timeline is a useful pressure test: manual renewal and deployment must disappear
before 100-day and 47-day public certificate operations become normal.

## P0: Production Safety

### Migration And Recovery

- Run PostgreSQL migration integration tests in CI against a disposable database.
- Add automated restore drills that verify schema version, audit state, issuer
  key references, CRL artifacts, OCSP responder state, and lifecycle jobs.

### Inventory, Ownership, And Expiry Control

- Move operator inventory filters from service-side filtering into SQL when large
  inventory tests show response time risk.
- Keep discovery/import scoped to the first real source requested by operators;
  defer broad network, Kubernetes, JKS, Windows Store, CDN, and Vault scanners
  until one integration proves the model.

### Webhook And Outbox Safety

- Add generated webhook receiver examples for common operator languages.
- Add bulk dead-letter replay tooling with event-type and time-window guards.

### Public TLS Readiness

- Enforce configurable public TLS validity ceilings for 200/100/47-day eras.
- Track Domain/IP validation reuse age separately from certificate validity.
- Add policy checks for CAA DNSSEC handling and RFC 8657 CAA parameters where
  public TLS issuance is enabled.
- Add mass-revocation planning docs and a tabletop drill checklist.

## P1: ACME Security And Compatibility

### Real Client Coverage

- Run certbot smoke from Linux or elevated Windows.
- Run lego smoke as a local regression command.
- Convert certbot/lego differences into protocol fixture tests.
- Build compatibility matrix for client, OS, account key type, challenge type,
  and smoke result.

### Multi-Node Nonce Safety

- Decide SQL-backed nonce store vs signed stateless nonce.
- Implement the chosen shared nonce strategy.
- Limit memory nonce behavior to local/single-node mode if shared nonce is added.
- Add replay tests that simulate multiple service nodes.

### HTTP-01 Egress Policy

- Harden DNS rebinding defenses.
- Validate resolver result and dialed address consistency.
- Make connect timeout, read timeout, redirect limit, and scheme policy explicit.
- Add tests for unsafe redirect targets.
- Add optional egress allow/deny list only if static safety rules prove
  insufficient.

### ACME Completeness

- Add account key coverage for RSA, ECDSA P-256, and Ed25519 where clients expose
  them.
- Bind KID/account URL validation to configured ACME base URL.
- Add account key rollover support.
- Add ACME revocation endpoint.
- Add External Account Binding if a real subscriber/account integration requires
  it.
- Add DNS-01 only when an operator-owned DNS provider integration is selected.
- Add rate limits for ACME account/order/challenge/finalize paths.
- Add RFC 8555 conformance matrix.

## P2: Operator Surface

### Documentation And Release Readiness

- Get owner decision for `LICENSE`.
- Add README license status.
- Write project scope covering public TLS, private CA, internal mTLS, device
  certificates, code signing, and explicit non-goals.
- Write target architecture docs for RA/API, policy engine, lifecycle service,
  issuer adapters, key providers, deploy adapters, audit, CRL, and OCSP.
- Write production deployment guide with secure sample config.
- Write bootstrap API key provisioning/removal/rotation runbook.
- Write state transition reference.
- Write API error code reference.
- Write OpenAPI spec for lifecycle/operator APIs.
- Write release process.
- Write incident response runbook for mis-issuance, key exposure, CA outage,
  failed renewal, failed revocation, and webhook outage.
- Write backup/restore runbook.
- Add compliance matrix for RFC 5280, RFC 6960, RFC 8555, CA/B Forum BR,
  Mozilla root-store expectations, NIST SP 800-57, and NIST SP 1800-16.

### Observability And Audit

- Add structured logs.
- Add metrics for issuance, revocation, renewal, reissue, suspension, CRL, OCSP,
  ACME, webhook, auth, DB, signer, core CLI, and expiration-scan boundaries.
- Add auth failure metrics.
- Add rate-limit metrics.
- Add trace/span ID propagation where useful.
- Add audit fields: auth method, API key fingerprint, user agent, state
  transition, approval reason, policy decision reason, validation evidence ref,
  old/new serial on renewal, and deployment target when available.
- Add audit pagination and retention policy.
- Add append-only or tamper-evident audit storage plan.
- Add SIEM export format and detection examples for issuance, revocation, policy
  change, key-provider use, and CA operations.
- Add secret redaction tests for logs and audit records.

### API Scale

- Add pagination/filter/sort for identities.
- Add pagination/filter/sort for certificates.
- Add pagination/filter/sort for enrollments.
- Add pagination/filter/sort for audit events.
- Add pagination/filter/sort for outbox messages.
- Add filters for owner, service, environment, issuer, profile, SAN, expiration
  window, revocation state, and renewal state.
- Add indexes only for exposed query patterns.
- Add large inventory tests for stable ordering and response time.

## P3: Key Boundary And Core Robustness

### HSM, KMS, And PKCS#11

- Define issuer/responder key reference model for HSM/KMS-backed keys.
- Separate file key provider from PKCS#11 signing provider.
- Document file provider as local/dev unless explicitly configured otherwise.
- Add API and audit behavior for non-exportable keys.
- Add key ceremony and intermediate rollover docs.
- Add offline-root operating model if this project owns CA hierarchy operations.
- Add audit tests proving key material is never recorded.
- Add PKCS#11 mock or software-token test path.

### Policy And Certificate Correctness

- Add profile-level key algorithm policy.
- Add profile-level signature algorithm policy.
- Add serial-number collision/entropy tests.
- Add public TLS linting hook before issuance if public TLS issuance is enabled.
- Add issued-certificate golden tests that parse DER and assert SAN, KU, EKU,
  BasicConstraints, AIA, CRL Distribution Points, SKI, and AKI.
- Add negative tests for CN-only requests, missing SAN, wildcard policy, IP SAN
  policy, invalid EKU/KU combinations, weak keys, expired chains, name
  constraints, malformed PEM, duplicate serials, and oversized SAN lists.

### Core CLI Contract

- Define JSON schema for Go-to-core CLI calls.
- Add contract tests for the Go/C++ boundary.
- Expose structured OpenSSL error details where useful for operator diagnosis.
- Add CSR parser fuzz target.
- Add OCSP parser fuzz target.
- Add CRL parser fuzz target.
- Document local fuzz commands.

## P4: Product Expansion

- Add certificate rotation automation that includes deploy target update,
  post-deploy health check, rollback, and operator notification.
- Add deploy adapters only after an operator picks concrete first targets; likely
  first targets are Kubernetes Secret and load balancer.
- Add Kubernetes workload identity.
- Add CT or external certificate monitoring for public DNS names.
- Add crypto deprecation/migration plan.
- Add crypto agility registry for key algorithm, signature algorithm, provider,
  and profile compatibility.
- Add PQC/hybrid experiments with clear non-production labeling.
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
- Reject large file splitting until repeated changes prove a stable boundary.
- Reject new abstractions until two real implementations exist or current code
  blocks a concrete requirement.
- Reject new dependencies unless stdlib/native code is materially worse.
- Reject new product surface while production safety, ACME compatibility,
  migration safety, key-boundary, and recovery docs remain incomplete.
