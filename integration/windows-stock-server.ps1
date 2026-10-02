param([ValidateSet('Start','Stop')][string]$Action = 'Start',
      [string]$Java = "$env:JAVA_HOME/bin/java.exe")
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $PSScriptRoot '.local'
$serverRoot = Join-Path $fixture 'server'
$pidFile = Join-Path $fixture 'server-process.txt'
$serverExe = Join-Path $serverRoot 'vpnserver_x64.exe'
if ($Action -eq 'Stop') {
    if (Test-Path -LiteralPath $pidFile) {
        $fixturePid = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
        $process = Get-Process -Id $fixturePid -ErrorAction SilentlyContinue
        if ($null -ne $process) {
            if ($process.Path -ne $serverExe) { throw 'PID does not belong to this fixture; refusing to stop it' }
            Stop-Process -Id $fixturePid
        }
    }
    return
}
if (Test-Path -LiteralPath $pidFile) {
    $fixturePid = [int](Get-Content -LiteralPath $pidFile -Raw).Trim()
    $running = Get-Process -Id $fixturePid -ErrorAction SilentlyContinue
    if ($null -ne $running -and $running.Path -eq $serverExe) {
        Write-Output 'This stock fixture is already running.'; return
    }
}
$sevenZip = 'C:/Program Files/7-Zip/7z.exe'
if (-not (Test-Path -LiteralPath $sevenZip)) { throw 'Install 7-Zip or adjust its path for fixture extraction' }
New-Item -ItemType Directory -Force -Path $fixture | Out-Null
$installer = Join-Path $fixture 'stock-server.exe'
if (-not (Test-Path -LiteralPath $installer)) {
    Invoke-WebRequest -UseBasicParsing -Uri 'https://jp.softether-download.com/files/softether/v4.44-9807-rtm-2025.04.16-tree/Windows/SoftEther_VPN_Server_and_VPN_Bridge/softether-vpnserver_vpnbridge-v4.44-9807-rtm-2025.04.16-windows-x86_x64-intel.exe' -OutFile $installer
}
$signature = Get-AuthenticodeSignature -LiteralPath $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'SOFTETHER CORPORATION') {
    throw 'Stock installer signature did not validate'
}
Push-Location $workspace
try {
    & $sevenZip x $installer "-o$fixture/extracted" '.rsrc/0/DATAFILE/*' -y | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Installer resource extraction failed' }
    @'
from pathlib import Path
import zlib, struct
root = Path('integration/.local')
source = root / 'extracted/.rsrc/0/DATAFILE'
target = root / 'server'
target.mkdir(exist_ok=True)
for name in ('VPNSERVER_X64.EXE', 'VPNCMD_X64.EXE'):
    data = (source / name).read_bytes()
    result = zlib.decompress(data[4:])
    assert len(result) == struct.unpack('>I', data[:4])[0] and result[:2] == b'MZ'
    (target / name.lower()).write_bytes(result)
(target / 'hamcore.se2').write_bytes((source / 'RAW_HAMCORE.SE2').read_bytes())
'@ | python -
    if ($LASTEXITCODE -ne 0) { throw 'Stock binary decompression failed' }
    if (-not (Test-Path -LiteralPath "$serverRoot/vpn_server.config")) {
        & $Java --class-path 'integration/build/install/integration/lib/*' integration/FixtureConfig.java $serverRoot
        if ($LASTEXITCODE -ne 0) { throw 'Build :integration:installDist before starting the fixture' }
        Move-Item -LiteralPath "$serverRoot/password.txt" -Destination "$fixture/password.txt" -Force
    }
    if ((Get-AuthenticodeSignature -LiteralPath $serverExe).Status -ne 'Valid') { throw 'Extracted stock binary is not signed' }
    $process = Start-Process -FilePath $serverExe -ArgumentList '/usermode_hidetray' -WorkingDirectory $serverRoot -WindowStyle Hidden -PassThru
    Set-Content -LiteralPath $pidFile -Value $process.Id
    Start-Sleep -Seconds 3
    $vpncmd = Join-Path $serverRoot 'vpncmd_x64.exe'
    $admin = (Get-Content -LiteralPath "$serverRoot/admin-password.txt" -Raw).Trim()
    $testPassword = (Get-Content -LiteralPath "$fixture/password.txt" -Raw).Trim()
    & $vpncmd localhost:5555 /SERVER "/PASSWORD:$admin" /CMD ServerInfoGet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture server did not start' }
    foreach ($hub in @('TEST','NODHCP')) {
        & $vpncmd localhost:5555 /SERVER "/PASSWORD:$admin" /CMD HubCreate $hub "/PASSWORD:$admin" | Out-Null
        & $vpncmd localhost:5555 /SERVER "/HUB:$hub" "/PASSWORD:$admin" /CMD UserCreate test /GROUP:none /REALNAME:none /NOTE:none | Out-Null
        & $vpncmd localhost:5555 /SERVER "/HUB:$hub" "/PASSWORD:$admin" /CMD UserPasswordSet test "/PASSWORD:$testPassword" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Fixture user setup failed' }
    }
    & $vpncmd localhost:5555 /SERVER /HUB:TEST "/PASSWORD:$admin" /CMD SecureNatEnable | Out-Null
    $cert = Join-Path $fixture 'server.crt'
    & $vpncmd localhost:5555 /SERVER "/PASSWORD:$admin" /CMD ServerCertGet $cert | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture certificate export failed' }
    & tools/get-certificate-pin.ps1 -CertificatePath $cert | Set-Content -LiteralPath "$fixture/pin.txt"
    Write-Output 'Stock Stable 4.44 fixture ready: localhost TCP5555 and direct UDP53. Synthetic credentials remain in .local.'
} finally { Pop-Location; $admin = $null; $testPassword = $null }
