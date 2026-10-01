[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$CertificatePath)

$ErrorActionPreference = 'Stop'
$resolvedCertificate = (Resolve-Path -LiteralPath $CertificatePath).Path
$certificateBytes = [IO.File]::ReadAllBytes($resolvedCertificate)
if ($certificateBytes.Length -lt 1 -or $certificateBytes.Length -gt 1048576) {
    throw 'Certificate file size is invalid'
}

# A fingerprint hashes the certificate's DER bytes, not its PEM text file.
# Support both forms of SoftEther's public X.509 certificate export.
$certificateText = [Text.Encoding]::ASCII.GetString($certificateBytes)
if ($certificateText.Contains('-----BEGIN CERTIFICATE-----')) {
    $pem = [regex]::Match($certificateText, '(?s)-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----')
    if (-not $pem.Success) { throw 'Malformed PEM certificate' }
    $certificateBytes = [Convert]::FromBase64String($pem.Groups[1].Value)
}
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificateBytes)
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
    ([BitConverter]::ToString($sha256.ComputeHash($certificate.RawData))).Replace('-', '')
} finally {
    $sha256.Dispose()
    $certificate.Dispose()
}
