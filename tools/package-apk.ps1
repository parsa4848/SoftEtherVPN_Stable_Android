$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$apk = Join-Path $workspace 'app\build\outputs\apk\debug\app-debug.apk'
if (-not (Test-Path -LiteralPath $apk)) { throw 'Build :app:assembleDebug first' }
$distribution = Join-Path $workspace 'dist'
New-Item -ItemType Directory -Force -Path $distribution | Out-Null
$metadata = Get-Content -LiteralPath (Join-Path $workspace 'app\build\outputs\apk\debug\output-metadata.json') -Raw | ConvertFrom-Json
$version = $metadata.elements[0].versionName
if ($version -notmatch '^\d+\.\d+\.\d+$') { throw 'Unexpected APK version' }
$filename = "SEVPN-$version-debug.apk"
$destination = Join-Path $distribution $filename
Copy-Item -LiteralPath $apk -Destination $destination
$sha = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath (Join-Path $distribution 'SHA256SUMS.txt') -Value "$sha  $filename" -Encoding ASCII
Write-Output $destination
Write-Output "SHA-256: $sha"
