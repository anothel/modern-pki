# Core Boundary Integration

Go unit tests use fake `modern-pki-core` commands for argument and JSON mapping
coverage. The integration contract test runs the real C++ CLI binary through
the Go runner and checks that structured command errors survive the process
boundary.

Build the C++ CLI first, then run:

```powershell
$env:MODERN_PKI_CORE_BIN = (Resolve-Path ..\build\Debug\modern-pki-core.exe).Path
go test ./internal/corecli -run CoreCLIIntegration -v
```

From Linux or a single-config build, point `MODERN_PKI_CORE_BIN` at the built
`modern-pki-core` executable.
