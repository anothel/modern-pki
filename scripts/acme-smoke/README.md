# ACME certbot smoke harness

This directory is for live ACME-client compatibility checks against a local
`modern-pki-service`.

The harness is intentionally small: it checks local client availability,
checks the ACME directory endpoint, prints the exact certbot command, and can
run it when `-Run` is supplied.

## Current local status

The current workspace shell does not have these clients on `PATH`:

- `certbot`
- `lego`
- `step`

Install one before expecting a live smoke run to complete. The first target is
certbot compatibility.

## Service precondition

Start the service separately:

```powershell
cd service
$env:MODERN_PKI_ADDR = "127.0.0.1:8080"
$env:MODERN_PKI_DB_DRIVER = "sqlite"
$env:MODERN_PKI_DB_DSN = "..\.tmp\acme-smoke\modern-pki.db"
$env:MODERN_PKI_CORE_BIN = "..\build\Debug\modern-pki-core.exe"
$env:MODERN_PKI_ACME_HTTP01_BASE_URL = "http://127.0.0.1:5002"
go run .\cmd\modern-pki-service
```

Then verify the ACME directory:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1
```

Run certbot when preflight is clean:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Run
```

## HTTP-01 local limitation

By default, `modern-pki` validates HTTP-01 by fetching:

```text
http://{identifier}/.well-known/acme-challenge/{token}
```

That means a local certbot smoke would normally need the requested domain to
resolve to the machine running certbot, and certbot standalone would need to
answer on port 80.

For smoke tests, set:

```powershell
$env:MODERN_PKI_ACME_HTTP01_BASE_URL = "http://127.0.0.1:5002"
```

Then the service fetches the challenge token from that base URL while certbot
answers on `-Http01Port 5002`.

The default smoke domain is:

```text
edge-01.example.test
```

For local-only testing without the override, map it to loopback in the system
hosts file, or change `-Domain` to a name that resolves locally. On Windows,
binding port 80 may require an elevated shell.
