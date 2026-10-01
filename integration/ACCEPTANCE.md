# Required device acceptance

Status: **pending**. No phone/emulator was connected to the build host. The
user tested 0.1.0 on a Poco X6 Pro, Android 16, against Stable 4.41-9787-rtm
on Windows Server 2019. Its diagnostics show repeated failures during
CONNECTING_TRANSPORT, before TLS, with zero tunnel traffic. The 0.1.1 update
fixes uninitialized socket protection and network callback races. Successful
retest is pending. No remote server credentials were supplied to the agent.

Record phone model/Android API, server Stable version/build, transport port,
hub network mode and test date. Never record passwords, hashes or session keys.

| Scenario | Required evidence | Status |
|---|---|---|
| Trusted CA certificate | Matching hostname validates without pin | Pending |
| Explicit self-signed pin | Correct SHA-256 identity connects; incorrect pin fails | Pending |
| Password authentication | Real session visible in hub manager | Pending |
| Wrong password / hub | Useful error, no Connected/TUN | Pending |
| DHCP success | Address/mask/gateway/DNS correspond to hub lease | Pending |
| DHCP unavailable | Clear error or reconnect state; no Connected | Pending |
| Consent rejected | Error and no VPN service/tunnel | Pending |
| Full IPv4 forwarding | Phone browser obtains server-side egress IP | Pending |
| DNS | Names resolve through hub DNS; capture/counters confirm tunneled UDP/TCP | Pending |
| TCP / UDP | Browser transfer and UDP traffic cross the hub | Pending |
| IPv6 | IPv6-only request blocked while VPN active | Pending |
| Disconnect | TUN/notification disappear; server session removed | Pending |
| Reconnect | Fresh authenticated session, DHCP and ARP state | Pending |
| Wi-Fi/mobile transition | Protected new physical socket and successful recovery | Pending |
| Network interruption | Controlled backoff, restoration succeeds | Pending |
| Disconnect during retry | Retry stops immediately | Pending |
| Android VPN revoke | Resources released, no reconnect | Pending |
| Lease renewal | Valid renewal or controlled reacquisition; no expired lease use | Pending |
| Keystore device test | connectedDebugAndroidTest passes | Pending |
| Sustained transfer | Bounded memory, realistic throughput and no false Connected | Pending |

Automated host tests cannot close these gates. Update only after observed
results. Preserve sanitized error export and server session evidence for
failures. Production readiness cannot be claimed until the required gates pass.
