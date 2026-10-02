# Real stock-server integration

The host runner uses the same core code as Android. It authenticates, obtains
DHCP, resolves example.com through the leased DNS server using IPv4 UDP, and
validates a checksummed TCP HTTP response carried inside native Ethernet
frames. These are real tunnel traffic probes; they do not establish Android
VpnService or substitute for the phone/browser acceptance test.

## Local unmodified Stable server

The Windows fixture has been executed against officially signed Stable 4.44
build 9807 binaries. It runs in user mode with fresh synthetic admin/user
passwords, no installed Windows service or TAP/kernel driver, and test hubs.
Its config disables DDNS, NAT-T discovery and ICMP; VPN-over-DNS is enabled.
Python 3, 7-Zip and a built integration distribution are required:

```powershell
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\gradlew.bat :integration:installDist
.\integration\windows-stock-server.ps1 -Action Start
.\integration\run-matrix.ps1
.\integration\run-transport-matrix.ps1
.\integration\windows-stock-server.ps1 -Action Stop
```

Setup verifies the installer/server signatures and extracts resources without
running the installer. Credentials remain in ignored `.local`. Management
uses TCP5555; R-UDP uses UDP53. These ports must be available. Keep `.local`
private. Stop the fixture before JVM tests: the stream test also binds UDP53.
Stop checks the recorded PID's executable path. Executed evidence is in
[TEST_RESULTS.md](../TEST_RESULTS.md); Android VpnService remains a separate gate.

### Docker alternative

Install Docker with Linux amd64 support, then from the project root:

```sh
docker compose -f integration/compose.yaml up --build -d
docker compose -f integration/compose.yaml logs -f
```

The image builds the stock pinned Stable source, without patches. Configuration
creates TEST with SecureNAT/DHCP, NODHCP without DHCP, password users and a guest
anonymous user. It installs an ephemeral certificate with localhost SAN.
Only localhost TCP5555, UDP53 and UDP40000–40100 are published; the stock
server assigns acceleration ports starting at 40000. VPN-over-DNS is enabled.
This Docker fixture uses an empty management
password and **must remain bound to loopback**; never expose it on a public
interface. Generated test password, private key, certificate and fingerprint
are in ignored `integration/.local/`, mode 0600 on Unix.

Docker/WSL are unavailable on this host, so the Docker alternative is untested.
The executed integration evidence uses the signed Windows fixture above.

```powershell
.\gradlew.bat :integration:installDist
$env:JAVA_HOME = 'C:\Program Files\Android\Android Studio\jbr'
.\integration\run-matrix.ps1
```

The matrix covers pinned self-signed trust, native auth/session, DHCP, UDP DNS,
TCP HTTP, incorrect credentials, missing hub, default rejection of a self-signed
certificate, incorrect pin, no DHCP and a second complete connection.

The transport matrix exercises 1/2/4/8/32 TCP connections, secondary loss and
restoration, acceleration v2, UDP loss with TCP continuation, and explicit
R-UDP/DNS with zero TCP connections. Local Windows `vpncmd` independently
checks held single-session logins with server `SessionGet` for 2/4/8/32.
Additional observed checks cover server clamping, declined acceleration, v1
real data, UDP53 TLS rejection and disabled UDP53 with reachable TCP.

With a connected phone/emulator:

```powershell
.\gradlew.bat :app:connectedDebugAndroidTest
```

Platform instrumentation exercises real Android Keystore; unit tests run on
the JVM. The APK does not need a test-server password embedded in the source.

## Existing server

Use the generated runner executable from a terminal. Parameters contain no
password: `host port hub username [pin|-] [scenario] [connections] [transport]
[udp-mode] [hold-seconds]`. Default scenario is
`traffic`. Set the temporary process environment variable SEVPN_TEST_PASSWORD
from a secure local prompt, or run a terminal with Java Console support.
Never put real secrets in source, command arguments or saved scripts.

```powershell
$secret = Read-Host 'Test server password' -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
try {
    $env:SEVPN_TEST_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    .\integration\build\install\integration\bin\integration.bat vpn.example.org 443 HUB user - traffic
} finally {
    Remove-Item Env:SEVPN_TEST_PASSWORD -ErrorAction SilentlyContinue
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
```

For private servers replace `-` with the verified leaf SHA-256 fingerprint.
Other scenarios: `login`, `error:9` (supply a deliberately wrong password),
`error:8` (supply a missing hub), `no-dhcp` (a configured user on a hub without
DHCP), and `tls-error`. No authentication failure is counted as a DHCP failure.

Transport is `TCP`, `AUTO` or `RUDP_DNS_53`; UDP mode is `udp-off`, `udp-on`
(v2) or `udp-v1`. `secondary-loss` and `udp-drop` close a socket then require
another DNS/HTTP exchange in the same session. `udp-unavailable` requires the
hub option `ExtOptionSet DisableUdpAcceleration /VALUE:1`. `rudp-failure`
requires explicit UDP53 and a stopped DNS listener. Use the stock command
`VpnOverIcmpDnsEnable /ICMP:no /DNS:yes` to enable DNS transport. Restore test
policies/listeners after a negative test.

Normal trusted validation with the fixture certificate can be tested by
importing it into a **test-only** Java truststore and setting JAVA_OPTS with
javax.net.ssl.trustStore/trustStorePassword, then running with `-` for the pin.
The localhost SAN must match. On Android, use normal system-trusted certificates
or explicit pinning; the host truststore is not an Android app feature.

## Traces and official-client comparison

Inspect session/client product, virtual MAC and address in the hub manager.
Configure the official desktop client for TLS encryption, no compression,
one connection, QoS off and UDP acceleration off. Compare handshake field
types, signature acceptance, session welcome and Ethernet packet sizes.
TLS captures alone do not expose PACK; use an isolated synthetic-credential
fixture for server debug instrumentation, never a production credential trace.
Keep packet traces outside Git and treat captures as sensitive.

On the Docker fixture, pause/unpause the container to simulate transport loss.
On the phone test Wi-Fi/mobile changes, no network, user disconnect and OS
revocation. Record actual outcomes in [ACCEPTANCE.md](ACCEPTANCE.md).

Clean up this fixture with `docker compose -f integration/compose.yaml down`.
Generated test private material remains under `.local` for explicit local
removal; it is never added to Git or packaged into the Android application.
