$ErrorActionPreference = 'Stop'
$binary = Join-Path (Split-Path -Parent $PSScriptRoot) 'build/wintriage.exe'
$reportPath = Join-Path $env:TEMP ("wintriage-udp-{0}.json" -f [guid]::NewGuid())
$sockets = @()
try {
    # Bound loopback sockets create test endpoints without sending packets.
    foreach ($address in @('127.0.0.1', '::1')) {
        $ip = [System.Net.IPAddress]::Parse($address)
        $socket = [System.Net.Sockets.Socket]::new(
            $ip.AddressFamily, [System.Net.Sockets.SocketType]::Dgram,
            [System.Net.Sockets.ProtocolType]::Udp)
        $sockets += $socket
        $socket.Bind([System.Net.IPEndPoint]::new($ip, 0))
    }
    & $binary --output $reportPath
    if ($LASTEXITCODE -ne 0) { throw 'Report collection failed.' }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($null -eq $report.udp_endpoints) { throw 'UDP inventory is missing.' }
    if ($null -eq $report.udp_collection_errors) { throw 'UDP collection status is missing.' }
    foreach ($family in @('IPv4', 'IPv6')) {
        if ($null -ne $report.udp_collection_errors.$family) {
            throw "UDP $family collection failed."
        }
    }
    foreach ($socket in $sockets) {
        $endpoint = $socket.LocalEndPoint
        $family = if ($endpoint.AddressFamily -eq 'InterNetwork') { 'IPv4' } else { 'IPv6' }
        $found = @($report.udp_endpoints | Where-Object {
            $_.pid -eq $PID -and $_.local_address -eq $endpoint.Address.ToString() -and
            $_.local_port -eq $endpoint.Port -and $_.address_family -eq $family
        })
        if ($found.Count -ne 1) { throw "Expected one matching $family test endpoint." }
        if ($found[0].local_scope_id -ne 0) { throw 'Unexpected loopback scope ID.' }
        if ($found[0].PSObject.Properties.Name -contains 'remote_address') {
            throw 'UDP endpoints should not invent remote peers.'
        }
    }
    Write-Host 'UDP IPv4/IPv6 address, port, PID, and JSON checks passed.'
} finally {
    foreach ($socket in $sockets) { $socket.Dispose() }
    if (Test-Path -LiteralPath $reportPath) { Remove-Item -LiteralPath $reportPath -Force }
}
