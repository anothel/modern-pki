# ACME certbot smoke harness

This directory is for live ACME-client compatibility checks against a local
`modern-pki-service`.

The harness is intentionally small: it checks the ACME directory endpoint,
prints the exact certbot command, and can run it when `-Run` is supplied.
Preflight mode does not require certbot to be installed. Live run mode does
require certbot and exits `2` when certbot is missing.

## Current local status

The current workspace shell does not have these clients on `PATH`:

- `certbot`
- `lego`
- `step`

Install certbot before expecting a live smoke run to complete. The first target
is certbot compatibility.

## Service modes

You can run against a separately started service, or let the harness start a
temporary local service with `-StartService`.

### Separate service

Start the service separately when you want to control the service process:

```powershell
cd service
$env:MODERN_PKI_ADDR = "127.0.0.1:8080"
$env:MODERN_PKI_DB_DRIVER = "sqlite"
$env:MODERN_PKI_DB_DSN = "..\.tmp\acme-smoke\modern-pki.db"
$env:MODERN_PKI_CORE_BIN = "..\build\Debug\modern-pki-core.exe"
$env:MODERN_PKI_ACME_HTTP01_BASE_URL = "http://127.0.0.1:5002"
go run .\cmd\modern-pki-service
```

Then verify the ACME directory in preflight mode:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1
```

Run certbot when preflight is clean and certbot is installed:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -Run
```

### Harness-started service

Use `-StartService` when you want the harness to start `modern-pki-service`
with temporary SQLite state:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -StartService
```

For a live certbot run with the harness-started service:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\acme-smoke\run-certbot-smoke.ps1 -StartService -Run
```

`-StartService` starts the service with:

- `MODERN_PKI_DB_DRIVER=sqlite`
- a temporary SQLite database under `.tmp\acme-smoke`
- `MODERN_PKI_ACME_HTTP01_BASE_URL=http://127.0.0.1:{Http01Port}`

Logs and temporary state are written under `.tmp\acme-smoke`.

## Preflight and live run

The default mode is preflight. It does not invoke certbot and works without
certbot installed. Use it to verify the local service and inspect the certbot
command that would be run.

`-Run` performs the live certbot smoke. In this mode, certbot must be available
on `PATH`; if it is missing, the harness exits `2`.

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

DNS-01 is out of scope for this harness.
