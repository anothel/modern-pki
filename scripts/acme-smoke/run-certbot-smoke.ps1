param(
    [string]$ServiceUrl = "http://127.0.0.1:8080",
    [string]$Domain = "edge-01.example.test",
    [string]$Email = "ops@example.test",
    [string]$WorkDir = ".tmp\acme-smoke",
    [int]$Http01Port = 5002,
    [string]$CertbotPath = "certbot",
    [switch]$StartService,
    [string]$ServiceProjectPath = "service",
    [string]$CoreBin = "build\Debug\modern-pki-core.exe",
    [string]$DbDsn = ".tmp\acme-smoke\modern-pki.db",
    [string]$ServiceLogDir = ".tmp\acme-smoke\service-logs",
    [int]$DirectoryTimeoutSec = 20,
    [switch]$Run
)

$ErrorActionPreference = "Stop"

function Resolve-SmokePath {
    param([string]$Path)

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path (Get-Location) $Path
}

function Escape-SingleQuotedPowerShell {
    param([string]$Value)

    return $Value.Replace("'", "''")
}

function Resolve-OptionalCommand {
    param([string]$NameOrPath)

    if (Test-Path -LiteralPath $NameOrPath -PathType Leaf) {
        return [pscustomobject]@{ Source = (Resolve-Path -LiteralPath $NameOrPath).Path }
    }

    $command = Get-Command $NameOrPath -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        return $null
    }
    return [pscustomobject]@{ Source = $command.Source }
}

function Test-ACMEDirectory {
    param([string]$BaseUrl)

    $directoryUrl = "$BaseUrl/acme/directory"
    try {
        $response = Invoke-RestMethod -Uri $directoryUrl -Method Get -TimeoutSec 5
    } catch {
        return [pscustomobject]@{
            Status = 3
            Message = $_.Exception.Message
        }
    }

    if ($null -eq $response.newNonce -or $null -eq $response.newAccount -or $null -eq $response.newOrder) {
        return [pscustomobject]@{
            Status = 4
            Message = "ACME directory missing required fields: $directoryUrl"
        }
    }
    return [pscustomobject]@{
        Status = 0
        Message = "ACME directory ready: $directoryUrl"
    }
}

function Wait-ACMEDirectory {
    param(
        [string]$BaseUrl,
        [int]$TimeoutSec
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSec)
    $last = $null
    do {
        $last = Test-ACMEDirectory $BaseUrl
        if ($last.Status -eq 0 -or $last.Status -eq 4) {
            return $last
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    return [pscustomobject]@{
        Status = 3
        Message = "ACME directory unavailable before timeout: $BaseUrl/acme/directory; last error: $($last.Message)"
    }
}

function Start-SmokeService {
    param(
        [string]$ServiceUrl,
        [string]$ServiceProjectPath,
        [string]$CoreBin,
        [string]$DbDsn,
        [string]$ServiceLogDir,
        [int]$Http01Port
    )

    $serviceUri = [Uri]$ServiceUrl
    $serviceAddr = "$($serviceUri.Host):$($serviceUri.Port)"
    $serviceProject = Resolve-SmokePath $ServiceProjectPath
    $coreBinPath = Resolve-SmokePath $CoreBin
    $dbDsnPath = Resolve-SmokePath $DbDsn
    $logDir = Resolve-SmokePath $ServiceLogDir
    $dbDir = Split-Path -Parent $dbDsnPath

    New-Item -ItemType Directory -Force -Path $dbDir, $logDir | Out-Null

    $stdout = Join-Path $logDir "modern-pki-service.stdout.log"
    $stderr = Join-Path $logDir "modern-pki-service.stderr.log"
    $http01BaseURL = "http://127.0.0.1:$Http01Port"
    $command = @"
`$ErrorActionPreference = 'Stop'
`$env:MODERN_PKI_ADDR = '$(Escape-SingleQuotedPowerShell $serviceAddr)'
`$env:MODERN_PKI_DB_DRIVER = 'sqlite'
`$env:MODERN_PKI_DB_DSN = '$(Escape-SingleQuotedPowerShell $dbDsnPath)'
`$env:MODERN_PKI_CORE_BIN = '$(Escape-SingleQuotedPowerShell $coreBinPath)'
`$env:MODERN_PKI_ACME_HTTP01_BASE_URL = '$(Escape-SingleQuotedPowerShell $http01BaseURL)'
Set-Location -LiteralPath '$(Escape-SingleQuotedPowerShell $serviceProject)'
go run .\cmd\modern-pki-service
"@

    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $process = Start-Process -FilePath "powershell" `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded) `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru

    return [pscustomobject]@{
        Process = $process
        Stdout = $stdout
        Stderr = $stderr
        HTTP01BaseURL = $http01BaseURL
    }
}

function Stop-SmokeService {
    param($ServiceProcess)

    if ($null -eq $ServiceProcess -or $null -eq $ServiceProcess.Process) {
        return
    }
    if (-not $ServiceProcess.Process.HasExited) {
        Stop-Process -Id $ServiceProcess.Process.Id -Force -ErrorAction SilentlyContinue
        $ServiceProcess.Process.WaitForExit(5000) | Out-Null
    }
}

$serviceProcess = $null

try {
    $certbot = Resolve-OptionalCommand $CertbotPath
    $certbotCommand = $CertbotPath
    if ($null -eq $certbot) {
        Write-Host "certbot unavailable: $CertbotPath"
        if ($Run) {
            Write-Host "install certbot or pass -CertbotPath before using -Run"
            exit 2
        }
    } else {
        $certbotCommand = $certbot.Source
    }

    if ($StartService) {
        $serviceProcess = Start-SmokeService `
            -ServiceUrl $ServiceUrl `
            -ServiceProjectPath $ServiceProjectPath `
            -CoreBin $CoreBin `
            -DbDsn $DbDsn `
            -ServiceLogDir $ServiceLogDir `
            -Http01Port $Http01Port
        Write-Host "started modern-pki-service pid: $($serviceProcess.Process.Id)"
        Write-Host "service stdout: $($serviceProcess.Stdout)"
        Write-Host "service stderr: $($serviceProcess.Stderr)"
        Write-Host "http-01 override: $($serviceProcess.HTTP01BaseURL)"
    }

    $directoryStatus = Wait-ACMEDirectory -BaseUrl $ServiceUrl -TimeoutSec $DirectoryTimeoutSec
    if ($directoryStatus.Status -ne 0) {
        Write-Host $directoryStatus.Message
        exit $directoryStatus.Status
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

    Write-Host "service: $ServiceUrl"
    Write-Host "domain: $Domain"
    Write-Host "http-01-port: $Http01Port"
    Write-Host "work-dir: $WorkDir"

    if (-not $Run) {
        Write-Host "preflight ok"
        Write-Host "run command:"
        Write-Host "$certbotCommand $($certbotArgs -join ' ')"
        exit 0
    }

    New-Item -ItemType Directory -Force -Path $configDir, $clientWorkDir, $logsDir | Out-Null
    & $certbot.Source @certbotArgs
    exit $LASTEXITCODE
} finally {
    Stop-SmokeService $serviceProcess
}
