param([string]$Runner = "$PSScriptRoot\build\install\integration\bin\integration.bat")
$ErrorActionPreference = 'Stop'
$pin = (Get-Content -LiteralPath "$PSScriptRoot\.local\pin.txt" -Raw).Trim()
$testPassword = (Get-Content -LiteralPath "$PSScriptRoot\.local\password.txt" -Raw).Trim()
$previousPassword = $env:SEVPN_TEST_PASSWORD
try {
    $env:SEVPN_TEST_PASSWORD = $testPassword
    & $Runner localhost 5555 TEST test $pin traffic
    if ($LASTEXITCODE -ne 0) { throw 'Traffic probe failed' }
    & $Runner localhost 5555 MISSING test $pin error:8
    if ($LASTEXITCODE -ne 0) { throw 'Wrong-hub probe failed' }
    & $Runner localhost 5555 TEST test - tls-error
    if ($LASTEXITCODE -ne 0) { throw 'Untrusted-certificate probe failed' }
    & $Runner localhost 5555 TEST test ('00' * 32) tls-error
    if ($LASTEXITCODE -ne 0) { throw 'Wrong-pin probe failed' }
    $env:SEVPN_TEST_PASSWORD = 'deliberately-wrong-test-password'
    & $Runner localhost 5555 TEST test $pin error:9
    if ($LASTEXITCODE -ne 0) { throw 'Wrong-password probe failed' }
    $env:SEVPN_TEST_PASSWORD = $testPassword
    & $Runner localhost 5555 NODHCP test $pin no-dhcp
    if ($LASTEXITCODE -ne 0) { throw 'No-DHCP probe failed' }
    & $Runner localhost 5555 TEST test $pin traffic
    if ($LASTEXITCODE -ne 0) { throw 'Reconnect probe failed' }
} finally { $env:SEVPN_TEST_PASSWORD = $previousPassword; $testPassword = $null }
