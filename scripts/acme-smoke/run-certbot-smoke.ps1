param(
    [string]$ServiceUrl = "http://127.0.0.1:8080",
    [string]$Domain = "edge-01.example.test",
    [string]$Email = "ops@example.test",
    [string]$WorkDir = ".tmp\acme-smoke",
    [int]$Http01Port = 5002,
    [switch]$Run
)

$ErrorActionPreference = "Stop"

function Resolve-RequiredCommand {
    param([string]$Name)

    return Get-Command $Name -ErrorAction SilentlyContinue
}

function Test-ACMEDirectory {
    param([string]$BaseUrl)

    $directoryUrl = "$BaseUrl/acme/directory"
    try {
        $response = Invoke-RestMethod -Uri $directoryUrl -Method Get -TimeoutSec 5
    } catch {
        Write-Host "ACME directory unavailable: $directoryUrl"
        Write-Host $_.Exception.Message
        return 3
    }

    if ($null -eq $response.newNonce -or $null -eq $response.newAccount -or $null -eq $response.newOrder) {
        Write-Host "ACME directory missing required fields: $directoryUrl"
        return 4
    }
    return 0
}

$certbot = Resolve-RequiredCommand "certbot"
if ($null -eq $certbot) {
    Write-Host "missing required command: certbot"
    Write-Host "install certbot or add it to PATH, then rerun this harness"
    exit 2
}

$directoryStatus = Test-ACMEDirectory $ServiceUrl
if ($directoryStatus -ne 0) {
    exit $directoryStatus
}

$configDir = Join-Path $WorkDir "config"
$clientWorkDir = Join-Path $WorkDir "work"
$logsDir = Join-Path $WorkDir "logs"
$server = "$ServiceUrl/acme/directory"

$certbotArgs = @(
    "certonly",
    "--server", $server,
    "--standalone",
    "--http-01-port", "$Http01Port",
    "--non-interactive",
    "--agree-tos",
    "--email", $Email,
    "--no-eff-email",
    "--config-dir", $configDir,
    "--work-dir", $clientWorkDir,
    "--logs-dir", $logsDir,
    "-d", $Domain
)

Write-Host "certbot: $($certbot.Source)"
Write-Host "service: $ServiceUrl"
Write-Host "domain: $Domain"
Write-Host "http-01-port: $Http01Port"

if (-not $Run) {
    Write-Host "preflight ok"
    Write-Host "run command:"
    Write-Host "certbot $($certbotArgs -join ' ')"
    exit 0
}

New-Item -ItemType Directory -Force -Path $configDir, $clientWorkDir, $logsDir | Out-Null
& $certbot.Source @certbotArgs
exit $LASTEXITCODE
