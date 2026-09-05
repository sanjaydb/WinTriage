$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $repo "build\wintriage.exe"
$report = Join-Path $env:TEMP "wintriage-test-report.json"
$textFile = Join-Path $env:TEMP "wintriage-test-input.txt"

if (-not (Test-Path -LiteralPath $binary)) {
    throw "Build WinTriage before running the smoke test."
}

Set-Content -LiteralPath $textFile -Value "Synthetic WinTriage test input." -Encoding ASCII
& $binary --output $report --file $textFile
if ($LASTEXITCODE -ne 0) { throw "WinTriage returned $LASTEXITCODE." }

$result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
if ($result.tool -ne "WinTriage") { throw "Unexpected tool identifier." }
if ($result.schema_version -ne "1.0") { throw "Unexpected schema version." }
if (-not $result.system.computer) { throw "System information is missing." }
if ($result.processes.Count -lt 1) { throw "Process inventory is empty." }
if ($result.file_analysis.pe_kind -ne "not_pe") { throw "Text fixture was incorrectly identified as PE." }
if ($result.file_analysis.sha256 -notmatch '^[0-9a-f]{64}$') { throw "SHA-256 is invalid." }

Remove-Item -LiteralPath $report, $textFile -Force
Write-Host "WinTriage smoke test passed."
