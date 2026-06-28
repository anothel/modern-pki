# Release Evidence

This file records release artifact, supply-chain, and compatibility decisions.
Release candidates attach evidence here by command output or CI run URL.

## Tool Decisions

| Area | Selected tool | Evidence hook |
| --- | --- | --- |
| Go static analysis | `go vet ./...` | CI `go-service` job. |
| Go dependency vulnerability scan | `govulncheck` | CI `go-service` job via `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`. |
| Secret baseline | `scripts/security-baseline-scan.py` | CI `docs` job and README smoke checklist. |
| SBOM | `syft` CycloneDX JSON | Release workflow or release operator command before attaching artifacts. |
| Artifact signing | `cosign` keyless signing | Release workflow or release operator command for checksums, SBOM, and archives. |

## Release Artifacts

Pre-1.0 releases distribute archives, not installers or container images:

- source archive from the signed tag,
- `modern-pki-service` binary archive,
- `modern-pki-core` CLI binary archive,
- `SHA256SUMS`,
- CycloneDX SBOM JSON,
- cosign signatures and transparency-log references for archives, checksums,
  and SBOM.

Container images, OS packages, and Helm charts stay out until a deployment
target is selected.

## Compatibility Matrix

Each release candidate records this matrix in release notes:

| Area | Required evidence |
| --- | --- |
| OS | GitHub Actions Ubuntu result plus any Windows local verification used for release. |
| Go | `go version` from CI and release host; minimum follows `service/go.mod`. |
| OpenSSL | CMake configure output or package version used by C++ build. |
| SQLite | Go test result for memory/SQLite stores. |
| PostgreSQL | PostgreSQL integration job result and DSN major version. |
| lego | ACME smoke result when ACME behavior changed. |
| certbot | Linux or elevated Windows smoke result when environment exists. |

## Required Evidence Per Release Candidate

- `python scripts/validate-docs.py`
- `python scripts/test_validate_release_evidence.py`
- `python scripts/validate-release-evidence.py`
- `go test ./...`
- `go vet ./...`
- `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
- `go build ./cmd/modern-pki-service`
- `cmake --build build --config Debug`
- `ctest --test-dir build -C Debug --output-on-failure`
- SBOM command output from `syft`
- signature verification output from `cosign`
- compatibility matrix row evidence
