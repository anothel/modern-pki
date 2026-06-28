# Release Process

`modern-pki` is pre-1.0. This process creates a reviewed release candidate; it
does not publish packages by itself.

## Preconditions

- Roadmap completed items have been removed from [ROADMAP](../ROADMAP.md).
- Release scope is aligned with
  [Release readiness action plan](../reference/release-readiness-action-plan.md).
- `README.md`, `SECURITY.md`, service docs, and runbooks match behavior.
- No real secrets, private keys, DB dumps, or production certificates are in the
  working tree.
- Owner has decided whether the release is internal-only or public.

## Build And Test

Run service checks:

```powershell
cd service
$env:GOCACHE = "$PWD\..\.tmp\gocache"
go test ./...
go build ./cmd/modern-pki-service
```

Run core checks:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="$env:OPENSSL_ROOT_DIR"
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

Run optional smoke checks when tools are available:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\test-run-certbot-smoke.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Client lego -LegoPath .tmp\lego-bin\lego.exe -StartService -Run
```

Certbot smoke requires Linux or elevated Windows with certbot installed.

## Release Candidate Checklist

1. Confirm `git status --short` contains only intended files.
2. Run `git diff --check`.
3. Review endpoint, config, migration, and runbook changes.
4. Record exact verification commands and results.
5. Record known gaps from [ROADMAP](../ROADMAP.md), especially contract parity,
   PKI failure-mode coverage, certbot coverage, and deferred EAB/DNS-01
   conditions.
6. Attach compatibility evidence from
   [ACME client compatibility](../acme-client-compatibility.md) when ACME
   behavior changed.
7. Attach RFC 8555 evidence from
   [ACME conformance](../acme-rfc8555-conformance.md) when ACME behavior
   changed.
8. Attach route/OpenAPI, config/docs, API error mapping, docs validation, and
   secret baseline scan evidence from CI.
9. Attach SBOM, SAST/SCA, artifact signing, and compatibility matrix evidence
   once release tooling is selected.

## Version Metadata

Builds should set:

- `serviceVersion`
- `serviceCommit`
- `serviceBuildTime`

Verify the running service reports the expected values:

```powershell
curl.exe http://localhost:8080/version
```

## Approval

Before tagging or distributing:

- security-sensitive changes reviewed,
- deployment and rollback plan reviewed,
- backup and restore path confirmed,
- owner accepts remaining roadmap gaps,
- Apache-2.0 license status confirmed.

## Post-Release

1. Monitor `/readyz`, audit failures, outbox dead letters, expiration scan
   results, CRL publication, and OCSP health.
2. Record any release-specific operational notes in the next release candidate.
3. Move completed roadmap items out of the future roadmap.
