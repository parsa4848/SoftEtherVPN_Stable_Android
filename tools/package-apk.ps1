$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$apk = Join-Path $workspace 'app\build\outputs\apk\debug\app-debug.apk'
if (-not (Test-Path -LiteralPath $apk)) { throw 'Build :app:assembleDebug first' }
$distribution = Join-Path $workspace 'dist'
New-Item -ItemType Directory -Force -Path $distribution | Out-Null
$destination = Join-Path $distribution 'SEVPN-0.1.0-debug.apk'
Copy-Item -LiteralPath $apk -Destination $destination
$sha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $distribution 'SHA256SUMS.txt') -Value "$sha  SEVPN-0.1.0-debug.apk" -Encoding ASCII
Write-Output $destination
Write-Output "SHA-256: $sha"
