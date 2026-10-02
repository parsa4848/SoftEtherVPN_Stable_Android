# Required device acceptance

Status: **device acceptance pending for 0.2.0**. No phone/emulator is connected
and no emulator system image is installed. The user supplied a working 0.1.1
deployment as the baseline. The unchanged build and 44 tests were preserved
before extending it. Host interoperability now passes against officially
signed stock Stable 4.44/9807 on Windows: native authentication, DHCP, actual
IPv4 DNS/HTTP, multiple TCP, acceleration v1/v2 and direct R-UDP/DNS.
See [the executed evidence](../TEST_RESULTS.md). Host probes do not exercise
Android protection, TUN, UI or Wi-Fi/mobile handover.

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
| Profile migration | Existing encrypted password/identity retained; defaults 1/Off/TCP | Pending |
| TCP 1/2/4/8/32 | One session/TUN/lease; server SessionGet agrees with requested/negotiated/active | Pending |
| TCP server clamp | Requested 8/server allowed 4 shown correctly; traffic continues | Pending |
| Secondary TCP loss | Other sockets carry traffic; replacement protected; no DHCP/TUN restart | Pending |
| UDP Off | No acceleration socket/offer; normal TCP traffic | Pending |
| UDP v2 On | Stock negotiation plus bidirectional payload bytes; Active only after data | Pending |
| UDP unavailable/lost | Connected remains usable over TCP; readiness clears; probes can recover | Pending |
| UDP endpoint migration | New authenticated peer endpoint used; fresh mapping on physical handover | Pending |
| Direct UDP53 | Destination server IPv4:53; active TCP=0; TLS/auth/DHCP/TUN/Internet all succeed | Pending |
| UDP53 disabled | Clear R-UDP error while TCP listener still works; no silent fallback | Pending |
| Every underlay protected | Primary/additional TCP and both UDP types protected before activity | Pending |
| Repeated disconnect/reconnect | Stable app FD/job counts; all old socket workers terminate | Pending |

Automated host tests cannot close these gates. Update only after observed
results. Preserve sanitized error export and server session evidence for
failures. Production readiness cannot be claimed until the required gates pass.
