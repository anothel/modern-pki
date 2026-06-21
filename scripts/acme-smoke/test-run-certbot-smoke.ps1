param(
    [string]$Runner = (Join-Path $PSScriptRoot "run-certbot-smoke.ps1")
)

$ErrorActionPreference = "Stop"

function Assert-Equal {
    param(
        [string]$Name,
        [object]$Actual,
        [object]$Expected
    )

    if ($Actual -ne $Expected) {
        throw "$Name = $Actual, want $Expected"
    }
}

function Get-FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Start-DirectoryStub {
    param([int]$Port)

    $stubDir = ".tmp\acme-smoke-test"
    New-Item -ItemType Directory -Force -Path $stubDir | Out-Null
    $stubPath = Join-Path $stubDir "directory-stub-$Port.js"
    $script = @"
const http = require("http");
const port = $Port;
const server = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/acme/directory") {
    res.writeHead(200, {"content-type": "application/json"});
    res.end(JSON.stringify({
      newNonce: "http://127.0.0.1:$Port/acme/new-nonce",
      newAccount: "http://127.0.0.1:$Port/acme/new-account",
      newOrder: "http://127.0.0.1:$Port/acme/new-order"
    }));
    return;
  }
  res.writeHead(404);
  res.end();
});
server.listen(port, "127.0.0.1");
"@
    Set-Content -LiteralPath $stubPath -Value $script -Encoding ASCII
    return Start-Process -FilePath "node" -ArgumentList @($stubPath) -WindowStyle Hidden -PassThru
}

function Wait-DirectoryStub {
    param(
        [string]$ServiceUrl,
        [int]$TimeoutSec = 5
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSec)
    do {
        try {
            Invoke-RestMethod -Uri "$ServiceUrl/acme/directory" -TimeoutSec 1 | Out-Null
            return
        } catch {
            Start-Sleep -Milliseconds 100
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)

    throw "directory stub did not start: $ServiceUrl"
}

function Stop-DirectoryStub {
    param($Process)

    if ($null -ne $Process -and -not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
        $Process.WaitForExit(5000) | Out-Null
    }
}

function Invoke-Runner {
    param([string[]]$RunnerArgs)

    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $Runner @RunnerArgs 2>&1
    return [pscustomobject]@{
        ExitCode = $LASTEXITCODE
        Output = ($output -join [Environment]::NewLine)
    }
}

$parseErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($Runner, [ref]$null, [ref]$parseErrors) | Out-Null
Assert-Equal "parse error count" $parseErrors.Count 0

$port = Get-FreePort
$job = Start-DirectoryStub -Port $port
try {
    $serviceUrl = "http://127.0.0.1:$port"
    Wait-DirectoryStub -ServiceUrl $serviceUrl
    $missingCertbot = "definitely-missing-certbot-for-modern-pki-smoke"

    $preflight = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-CertbotPath", $missingCertbot,
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    if ($preflight.ExitCode -ne 0) {
        throw "preflight exit code without certbot = $($preflight.ExitCode), want 0`n$($preflight.Output)"
    }
    if ($preflight.Output -notmatch "certbot unavailable") {
        throw "preflight output missing certbot unavailable marker"
    }

    $runMissing = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", $serviceUrl,
        "-CertbotPath", $missingCertbot,
        "-WorkDir", ".tmp\acme-smoke-test",
        "-Run"
    )
    Assert-Equal "run exit code without certbot" $runMissing.ExitCode 2

    $unavailable = Invoke-Runner -RunnerArgs @(
        "-ServiceUrl", "http://127.0.0.1:1",
        "-CertbotPath", $missingCertbot,
        "-DirectoryTimeoutSec", "1",
        "-WorkDir", ".tmp\acme-smoke-test"
    )
    Assert-Equal "unavailable service exit code" $unavailable.ExitCode 3
} finally {
    Stop-DirectoryStub $job
}

Write-Host "run-certbot-smoke tests passed"
