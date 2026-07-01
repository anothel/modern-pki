param(
    [switch]$List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")

$steps = @(
    @{
        Name = "docs validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-docs.py"
        Command = @("python", "scripts\validate-docs.py")
    },
    @{
        Name = "webhook receiver verification tests"
        Dir = $RepoRoot
        Display = "python scripts\test_webhook_receiver_verification.py"
        Command = @("python", "scripts\test_webhook_receiver_verification.py")
    },
    @{
        Name = "local verification wrapper tests"
        Dir = $RepoRoot
        Display = "python scripts\test_verify_local.py"
        Command = @("python", "scripts\test_verify_local.py")
    },
    @{
        Name = "service contract validator tests"
        Dir = $RepoRoot
        Display = "python scripts\test_validate_service_contracts.py"
        Command = @("python", "scripts\test_validate_service_contracts.py")
    },
    @{
        Name = "service contract validation"
        Dir = $RepoRoot
        Display = "python scripts\validate-service-contracts.py"
        Command = @("python", "scripts\validate-service-contracts.py")
    },
    @{
        Name = "security baseline scanner tests"
        Dir = $RepoRoot
        Display = "python scripts\test_security_baseline_scan.py"
        Command = @("python", "scripts\test_security_baseline_scan.py")
    },
    @{
        Name = "security baseline scan"
        Dir = $RepoRoot
        Display = "python scripts\security-baseline-scan.py"
        Command = @("python", "scripts\security-baseline-scan.py")
    },
    @{
        Name = "Go tests"
        Dir = Join-Path $RepoRoot "service"
        Display = "go test ./..."
        Command = @("go", "test", "./...")
    },
    @{
        Name = "Go build"
        Dir = Join-Path $RepoRoot "service"
        Display = "go build ./cmd/modern-pki-service"
        Command = @("go", "build", "./cmd/modern-pki-service")
    }
)

if ($List) {
    foreach ($step in $steps) {
        Write-Output $step.Display
    }
    exit 0
}

foreach ($step in $steps) {
    Write-Host "==> $($step.Name)"
    Push-Location -LiteralPath $step.Dir
    try {
        $command = $step.Command
        & $command[0] @($command | Select-Object -Skip 1)
        if ($LASTEXITCODE -ne 0) {
            exit $LASTEXITCODE
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host "local verification ok"
