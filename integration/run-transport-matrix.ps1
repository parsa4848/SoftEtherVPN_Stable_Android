param(
    [string]$Java = "$env:JAVA_HOME/bin/java.exe",
    [string]$Vpncmd = "$PSScriptRoot/.local/server/vpncmd_x64.exe",
    [string]$AdminPasswordFile = "$PSScriptRoot/.local/server/admin-password.txt"
)
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$classpath = Join-Path $PSScriptRoot 'build/install/integration/lib/*'
$pin = (Get-Content -LiteralPath "$PSScriptRoot/.local/pin.txt" -Raw).Trim()
$previousPassword = $env:SEVPN_TEST_PASSWORD
$admin = if (Test-Path -LiteralPath $AdminPasswordFile) { (Get-Content -LiteralPath $AdminPasswordFile -Raw).Trim() } else { '' }
function Probe([string]$scenario, [int]$count, [string]$transport, [string]$udp) {
    & $Java -cp $classpath com.blockto.sevpn.integration.ProbeKt localhost 5555 TEST test $pin $scenario $count $transport $udp
    if ($LASTEXITCODE -ne 0) { throw "Failed: $scenario connections=$count transport=$transport udp=$udp" }
}
try {
    $env:SEVPN_TEST_PASSWORD = (Get-Content -LiteralPath "$PSScriptRoot/.local/password.txt" -Raw).Trim()
    foreach ($count in @(1,2,4,8,32)) { Probe traffic $count TCP udp-off }
    Probe secondary-loss 4 TCP udp-off
    Probe udp-drop 4 TCP udp-on
    Probe traffic 8 RUDP_DNS_53 udp-off
    if (Test-Path -LiteralPath $Vpncmd) {
        foreach ($count in @(2,4,8,32)) {
            $outPath = "$PSScriptRoot/.local/connections-$count.txt"
            $errPath = "$PSScriptRoot/.local/connections-$count-errors.txt"
            $startOptions = @{ FilePath = $Java; ArgumentList = @('-cp', ('"' + $classpath + '"'),
                'com.blockto.sevpn.integration.ProbeKt', 'localhost', '5555', 'TEST', 'test', $pin,
                'login', $count, 'TCP', 'udp-off', '5'); WorkingDirectory = $workspace;
                WindowStyle = 'Hidden'; RedirectStandardOutput = $outPath; RedirectStandardError = $errPath }
            $probeProcess = Start-Process @startOptions -PassThru
            $null = $probeProcess.Handle # Cache the handle before HasExited polling on Windows PowerShell.
            try {
                $deadline = (Get-Date).AddSeconds(60); $sessionName = $null
                while ((Get-Date) -lt $deadline -and -not $probeProcess.HasExited) {
                    $content = Get-Content -LiteralPath $outPath -Raw -ErrorAction SilentlyContinue
                    if ($content -match 'session=(SID-TEST-\d+)') { $sessionName = $Matches[1]; break }
                    Start-Sleep -Milliseconds 200
                }
                if ($null -eq $sessionName) { throw "Count $count probe did not establish" }
                $evidence = & $Vpncmd localhost:5555 /SERVER /HUB:TEST "/PASSWORD:$admin" /CMD SessionGet $sessionName
                if ($LASTEXITCODE -ne 0) { throw 'Server session inspection failed' }
                $line = ($evidence | Select-String -Pattern '^Number of TCP Connections\s*\|').ToString()
                if ($line -notmatch "\|\s*$count\s*$") { throw "Server connection count $count did not match" }
                Write-Output "PASS stock server verified one $sessionName with $count TCP connections"
                $probeProcess.WaitForExit()
                $probeProcess.Refresh()
                if ($probeProcess.ExitCode -ne 0) { throw 'Held login failed' }
            } finally { if (-not $probeProcess.HasExited) { Stop-Process -Id $probeProcess.Id } }
        }
    } else { Write-Output 'Server-side count check pending: supply -Vpncmd and -AdminPasswordFile' }
} finally { $env:SEVPN_TEST_PASSWORD = $previousPassword; $admin = $null }
