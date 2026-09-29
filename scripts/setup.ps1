$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$envPath = Join-Path (Get-Location) '.env'
if (-not (Test-Path -LiteralPath $envPath)) { New-Item -ItemType File -Path $envPath | Out-Null }
$existing = [System.IO.File]::ReadAllText($envPath)
$tokenBytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($tokenBytes)
$rng.Dispose()
$appToken = [Convert]::ToBase64String($tokenBytes)
$settings = [ordered]@{
    OPENROUTER_MODEL = 'deepseek/deepseek-v4.1-flash'
    FOURCORE_API_KEY = ''
    FOURCORE_BASE_URL = 'https://prod.fourcore.io'
    APP_TOKEN = $appToken
    LISTEN_ADDR = '127.0.0.1:8080'
    DATA_DIR = 'data'
    EXECUTION_ENABLED = 'false'
    ALLOWED_ENDPOINT_ASSETS = ''
    ALLOWED_EMAIL_ASSETS = ''
    ALLOW_ELEVATED = 'false'
    LATERAL_EXECUTOR_ENABLED = 'false'
    LATERAL_EXECUTOR_BASE_URL = ''
    LATERAL_SOURCE_EXECUTORS = ''
    LATERAL_EXECUTOR_TOKEN = ''
    LATERAL_EVIDENCE_PUBLIC_KEY = ''
    LATERAL_EVIDENCE_PUBLIC_KEYS = ''
    LATERAL_ALLOWED_DESTINATIONS = ''
    LATERAL_CREDENTIAL_REFS = ''
    LATERAL_DEFAULT_CREDENTIAL_REF = ''
    MAX_PLAN_ITEMS = '5'
    MAX_PLAN_ASSETS = '10'
    FOURCORE_RPM = '60'
    POLL_INTERVAL_SECONDS = '30'
    CORRELATION_WAIT_SECONDS = '120'
}
if ($existing -notmatch '(?m)^\s*(OPENROUTER_API_KEY|openrouter)\s*=') { $settings['OPENROUTER_API_KEY'] = '' }
$lines = New-Object System.Collections.Generic.List[string]
foreach ($entry in $settings.GetEnumerator()) {
    if ($existing -notmatch ('(?m)^\s*' + [regex]::Escape($entry.Key) + '\s*=')) {
        $lines.Add($entry.Key + '=' + $entry.Value)
    }
}
if ($lines.Count -gt 0) {
    [System.IO.File]::AppendAllText($envPath, "`n" + [string]::Join("`n", $lines) + "`n", (New-Object System.Text.UTF8Encoding($false)))
}
Write-Output 'Configuration prepared. Existing values and secrets were preserved. Set FOURCORE_API_KEY and asset scope in .env.'
