param(
    [string]$ServiceUrl = "http://127.0.0.1:8080",
    [string]$Domain = "edge-01.example.test",
    [string]$Email = "ops@example.test",
    [string]$WorkDir = ".tmp\acme-smoke",
    [int]$Http01Port = 5002,
    [ValidateSet("certbot", "lego")]
    [string]$Client = "certbot",
    [ValidateSet("webroot", "standalone")]
    [string]$ChallengeMode = "webroot",
    [string]$CertbotPath = "certbot",
    [string]$LegoPath = "lego",
    [switch]$StartService,
    [string]$ServiceProjectPath = "service",
    [string]$ServiceBin = ".tmp\acme-smoke\modern-pki-service.exe",
    [string]$HTTPSProxyBin = ".tmp\acme-smoke\acme-https-proxy.exe",
    [int]$HTTPSProxyPort = 8443,
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

function Resolve-WebRootPython {
    param([string]$CertbotPath)

    if (Test-Path -LiteralPath $CertbotPath -PathType Leaf) {
        $certbotDir = Split-Path -Parent (Resolve-Path -LiteralPath $CertbotPath).Path
        $venvPython = Join-Path $certbotDir "python.exe"
        if (Test-Path -LiteralPath $venvPython -PathType Leaf) {
            return [pscustomobject]@{ Source = (Resolve-Path -LiteralPath $venvPython).Path }
        }
    }

    return Resolve-OptionalCommand "python"
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
        [string]$ServiceBin,
        [string]$CoreBin,
        [string]$DbDsn,
        [string]$ServiceLogDir,
        [int]$Http01Port
    )

    $serviceUri = [Uri]$ServiceUrl
    $serviceAddr = "$($serviceUri.Host):$($serviceUri.Port)"
    $serviceProject = Resolve-SmokePath $ServiceProjectPath
    $serviceBinPath = Resolve-SmokePath $ServiceBin
    $coreBinPath = Resolve-SmokePath $CoreBin
    $dbDsnPath = Resolve-SmokePath $DbDsn
    $logDir = Resolve-SmokePath $ServiceLogDir
    $goCachePath = Resolve-SmokePath ".gocache"
    $goModCachePath = Resolve-SmokePath ".gomodcache"
    $dbDir = Split-Path -Parent $dbDsnPath
    $serviceBinDir = Split-Path -Parent $serviceBinPath
    $issuerKeyRef = Join-Path $dbDir "acme-smoke-issuer.key"

    New-Item -ItemType Directory -Force -Path $dbDir, $logDir, $serviceBinDir, $goCachePath, $goModCachePath | Out-Null

    $stdout = Join-Path $logDir "modern-pki-service.stdout.log"
    $stderr = Join-Path $logDir "modern-pki-service.stderr.log"
    $commandPath = Join-Path $logDir "modern-pki-service.start.ps1"
    $http01BaseURL = "http://127.0.0.1:$Http01Port"
    $command = @"
MODERN_PKI_ADDR=$serviceAddr
MODERN_PKI_DB_DRIVER=sqlite
MODERN_PKI_DB_DSN=$dbDsnPath
MODERN_PKI_CORE_BIN=$coreBinPath
MODERN_PKI_ACME_HTTP01_BASE_URL=$http01BaseURL
MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS=true
MODERN_PKI_ACME_DEFAULT_VALIDITY=24h
MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF=$issuerKeyRef
GOCACHE=$goCachePath
GOMODCACHE=$goModCachePath
SERVICE_BIN=$serviceBinPath
"@

    Set-Content -LiteralPath $commandPath -Value $command -Encoding ASCII

    $previousGoCache = $env:GOCACHE
    $previousGoModCache = $env:GOMODCACHE
    try {
        $env:GOCACHE = $goCachePath
        $env:GOMODCACHE = $goModCachePath
        Push-Location -LiteralPath $serviceProject
        try {
            $buildOutput = & go build -o $serviceBinPath .\cmd\modern-pki-service 2>&1
            if ($LASTEXITCODE -ne 0) {
                $buildOutput | Out-File -LiteralPath $stderr -Encoding utf8
                throw "build modern-pki-service failed; see $stderr"
            }
        } finally {
            Pop-Location
        }
    } finally {
        $env:GOCACHE = $previousGoCache
        $env:GOMODCACHE = $previousGoModCache
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $serviceBinPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $previousModernPKIAddr = $env:MODERN_PKI_ADDR
    $previousModernPKIDBDriver = $env:MODERN_PKI_DB_DRIVER
    $previousModernPKIDBDSN = $env:MODERN_PKI_DB_DSN
    $previousModernPKICoreBin = $env:MODERN_PKI_CORE_BIN
    $previousModernPKIACMEHTTP01BaseURL = $env:MODERN_PKI_ACME_HTTP01_BASE_URL
    $previousModernPKIACMEBootstrapDefaults = $env:MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS
    $previousModernPKIACMEDefaultValidity = $env:MODERN_PKI_ACME_DEFAULT_VALIDITY
    $previousModernPKIACMEBootstrapIssuerKeyRef = $env:MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF
    try {
        $env:MODERN_PKI_ADDR = $serviceAddr
        $env:MODERN_PKI_DB_DRIVER = "sqlite"
        $env:MODERN_PKI_DB_DSN = $dbDsnPath
        $env:MODERN_PKI_CORE_BIN = $coreBinPath
        $env:MODERN_PKI_ACME_HTTP01_BASE_URL = $http01BaseURL
        $env:MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS = "true"
        $env:MODERN_PKI_ACME_DEFAULT_VALIDITY = "24h"
        $env:MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF = $issuerKeyRef
        $process = [System.Diagnostics.Process]::Start($startInfo)
    } finally {
        $env:MODERN_PKI_ADDR = $previousModernPKIAddr
        $env:MODERN_PKI_DB_DRIVER = $previousModernPKIDBDriver
        $env:MODERN_PKI_DB_DSN = $previousModernPKIDBDSN
        $env:MODERN_PKI_CORE_BIN = $previousModernPKICoreBin
        $env:MODERN_PKI_ACME_HTTP01_BASE_URL = $previousModernPKIACMEHTTP01BaseURL
        $env:MODERN_PKI_ACME_BOOTSTRAP_DEFAULTS = $previousModernPKIACMEBootstrapDefaults
        $env:MODERN_PKI_ACME_DEFAULT_VALIDITY = $previousModernPKIACMEDefaultValidity
        $env:MODERN_PKI_ACME_BOOTSTRAP_ISSUER_KEY_REF = $previousModernPKIACMEBootstrapIssuerKeyRef
    }

    return [pscustomobject]@{
        Process = $process
        Stdout = $stdout
        Stderr = $stderr
        Command = $commandPath
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
    $stdoutText = $ServiceProcess.Process.StandardOutput.ReadToEnd()
    if ($stdoutText -ne "") {
        $stdoutText | Out-File -LiteralPath $ServiceProcess.Stdout -Encoding utf8 -Append
    }
    $stderrText = $ServiceProcess.Process.StandardError.ReadToEnd()
    if ($stderrText -ne "") {
        $stderrText | Out-File -LiteralPath $ServiceProcess.Stderr -Encoding utf8 -Append
    }
}

function Start-WebRootServer {
    param(
        [string]$CertbotPath,
        [string]$WebRootDir,
        [int]$Http01Port
    )

    $python = Resolve-WebRootPython $CertbotPath
    if ($null -eq $python) {
        Write-Host "python unavailable: required for webroot HTTP-01 mode"
        exit 5
    }

    New-Item -ItemType Directory -Force -Path $WebRootDir | Out-Null
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $python.Source
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = "-m http.server $Http01Port --bind 127.0.0.1 --directory `"$WebRootDir`""
    return [System.Diagnostics.Process]::Start($startInfo)
}

function Stop-WebRootServer {
    param($Process)

    if ($null -eq $Process) {
        return
    }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Start-HTTPSProxy {
    param(
        [string]$ServiceUrl,
        [string]$HTTPSProxyBin,
        [int]$HTTPSProxyPort
    )

    $proxyBinPath = Resolve-SmokePath $HTTPSProxyBin
    $proxyBinDir = Split-Path -Parent $proxyBinPath
    $goCachePath = Resolve-SmokePath ".gocache"
    $goModCachePath = Resolve-SmokePath ".gomodcache"
    New-Item -ItemType Directory -Force -Path $proxyBinDir, $goCachePath, $goModCachePath | Out-Null

    $previousGoCache = $env:GOCACHE
    $previousGoModCache = $env:GOMODCACHE
    try {
        $env:GOCACHE = $goCachePath
        $env:GOMODCACHE = $goModCachePath
        $buildOutput = & go build -o $proxyBinPath .\scripts\acme-smoke\acme-https-proxy.go 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "build ACME HTTPS proxy failed: $($buildOutput -join [Environment]::NewLine)"
        }
    } finally {
        $env:GOCACHE = $previousGoCache
        $env:GOMODCACHE = $previousGoModCache
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $proxyBinPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = "-listen 127.0.0.1:$HTTPSProxyPort -target $ServiceUrl"
    return [System.Diagnostics.Process]::Start($startInfo)
}

function Stop-HTTPSProxy {
    param($Process)

    if ($null -eq $Process) {
        return
    }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

$serviceProcess = $null
$webRootProcess = $null
$httpsProxyProcess = $null

try {
    $clientPath = $CertbotPath
    if ($Client -eq "lego") {
        $clientPath = $LegoPath
    }

    $clientCommand = $clientPath
    $clientExecutable = Resolve-OptionalCommand $clientPath
    if ($null -eq $clientExecutable) {
        Write-Host "$Client unavailable: $clientPath"
        if ($Run) {
            Write-Host "install $Client or pass the selected client path before using -Run"
            exit 2
        }
    } else {
        $clientCommand = $clientExecutable.Source
    }

    if ($StartService) {
        $serviceProcess = Start-SmokeService `
            -ServiceUrl $ServiceUrl `
            -ServiceProjectPath $ServiceProjectPath `
            -ServiceBin $ServiceBin `
            -CoreBin $CoreBin `
            -DbDsn $DbDsn `
            -ServiceLogDir $ServiceLogDir `
            -Http01Port $Http01Port
        Write-Host "started modern-pki-service pid: $($serviceProcess.Process.Id)"
        Write-Host "service command: $($serviceProcess.Command)"
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
    $webRootDir = Join-Path $WorkDir "http01-webroot"
    $server = "$ServiceUrl/acme/directory"
    if ($Client -eq "lego") {
        $server = "https://127.0.0.1:$HTTPSProxyPort/acme/directory"
    }
    $legoPath = Join-Path $WorkDir "lego"

    if ($Client -eq "lego") {
        $certbotArgs = @(
            "--server", $server,
            "--tls-skip-verify",
            "--accept-tos",
            "--email", $Email,
            "--domains", $Domain,
            "--path", $legoPath,
            "--http",
            "--http.webroot", $webRootDir,
            "run"
        )
    } elseif ($ChallengeMode -eq "standalone") {
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
    } else {
        $certbotArgs = @(
            "certonly",
            "--server", $server,
            "--webroot",
            "--webroot-path", $webRootDir,
            "--non-interactive",
            "--agree-tos",
            "--email", $Email,
            "--no-eff-email",
            "--config-dir", $configDir,
            "--work-dir", $clientWorkDir,
            "--logs-dir", $logsDir,
            "-d", $Domain
        )
    }

    Write-Host "service: $ServiceUrl"
    Write-Host "client: $Client"
    Write-Host "domain: $Domain"
    Write-Host "challenge-mode: $ChallengeMode"
    Write-Host "http-01-port: $Http01Port"
    Write-Host "work-dir: $WorkDir"

    if (-not $Run) {
        Write-Host "preflight ok"
        Write-Host "run command:"
        Write-Host "$clientCommand $($certbotArgs -join ' ')"
        exit 0
    }

    New-Item -ItemType Directory -Force -Path $configDir, $clientWorkDir, $logsDir | Out-Null
    if ($Client -eq "lego" -or $ChallengeMode -eq "webroot") {
        $webRootProcess = Start-WebRootServer -CertbotPath $CertbotPath -WebRootDir $webRootDir -Http01Port $Http01Port
        Write-Host "webroot server pid: $($webRootProcess.Id)"
        Write-Host "webroot path: $webRootDir"
    }
    if ($Client -eq "lego") {
        $httpsProxyProcess = Start-HTTPSProxy -ServiceUrl $ServiceUrl -HTTPSProxyBin $HTTPSProxyBin -HTTPSProxyPort $HTTPSProxyPort
        Write-Host "https proxy pid: $($httpsProxyProcess.Id)"
        Write-Host "https proxy directory: $server"
    }
    & $clientExecutable.Source @certbotArgs
    exit $LASTEXITCODE
} finally {
    Stop-HTTPSProxy $httpsProxyProcess
    Stop-WebRootServer $webRootProcess
    Stop-SmokeService $serviceProcess
}
