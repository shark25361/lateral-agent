$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$listenAddress = '127.0.0.1:8080'
$envPath = Join-Path (Get-Location) '.env'
if (Test-Path -LiteralPath $envPath) {
    $listenLine = Get-Content -LiteralPath $envPath | Where-Object { $_ -match '^\s*LISTEN_ADDR\s*=' } | Select-Object -Last 1
    if ($listenLine) {
        $configuredAddress = ($listenLine -split '=', 2)[1].Trim().Trim('"').Trim("'")
        if ($configuredAddress) { $listenAddress = $configuredAddress }
    }
}

$separator = $listenAddress.LastIndexOf(':')
if ($separator -gt 0 -and $separator -lt ($listenAddress.Length - 1)) {
    $healthHost = $listenAddress.Substring(0, $separator).Trim('[', ']')
    $healthPort = $listenAddress.Substring($separator + 1)
    if ($healthHost -eq '0.0.0.0' -or $healthHost -eq '::' -or $healthHost -eq '') { $healthHost = '127.0.0.1' }
    $healthUrl = "http://${healthHost}:${healthPort}/healthz"
    try {
        $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
        if ($health.status -eq 'ok') {
            Write-Host "FourCore agent is already running at http://${healthHost}:${healthPort}."
            exit 0
        }
    } catch {
        # No healthy agent is listening, so start one below.
    }
}

$goBinary = Join-Path (Get-Location) '.tools\go\bin\go.exe'
if (-not (Test-Path -LiteralPath $goBinary)) { $goBinary = 'go' }
& $goBinary run ./cmd/fourcore-agent
exit $LASTEXITCODE
