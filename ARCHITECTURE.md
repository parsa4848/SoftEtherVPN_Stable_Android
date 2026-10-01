# Architecture decision: Kotlin native client and virtual Ethernet endpoint

Status: implementation selected; device acceptance remains a separate gate.

## Evidence and alternatives

The authoritative source is the supplied SoftEtherVPN_Stable checkout,
`ed17437af9719ac66acab30faa29e375d613c35f` (4.44, build 9807).
`CiConnect` creates a VLAN packet adapter and `NewClientSessionEx`;
`ClientConnect` performs TLS, signature, hello, authentication, welcome and
switches the same socket to Ethernet data transport. `SessionMain` moves
Ethernet blocks between the adapter and `Connection.c` queues.

| Criterion | Kotlin client | Minimal Cedar/Mayaqua NDK port |
|---|---|---|
| Protocol correctness | Small explicitly negotiated subset; C-derived vectors and stock-server tests | Existing wire code, but many global/platform dependencies |
| Lifecycle | Closeable sockets and structured coroutine scope | JNI ownership, native threads, cancellation and global Cedar lifetime |
| Security | Platform TLS/Keystore; bounded managed parsers | Must audit native parsers, OpenSSL and vendored third parties |
| Testability | Pure JVM modules; same code in host integration runner | Cross-compilation and JNI/native test harness |
| Maintainability | Map every wire operation to pinned C functions | Maintain a sizeable platform-specific fork |
| Complexity | PACK, SHA-0 challenge, HTTP negotiation, TCP frames, ARP/DHCP | Mayaqua OS/Unix service, TLS, build assumptions, adapter and the same L2/L3 work |

Choose Kotlin. The Unix makefiles build broad Cedar/Mayaqua libraries and
`vpncsvc.c` starts an OS service. `VLanUnix.c` assumes TAP access. Porting that
executable does not solve Android packet adaptation. The minimum Android
reference confirms feasibility, but is not copied: it protects an already
connected TLS socket, does not explicitly enable endpoint identification,
and uses assertion-oriented parsers/shared mutable lifecycle state. Its
SHA-0 padding also needs boundary tests. See PROTOCOL_NOTES.md for the audit.

Stable's `/mvpn` dispatch is behind `if (false) // TODO`; it is never used.
Its L3 helper and `IPsec_IPC.c` provide useful ARP/DHCP design references.
PACK is actually in Mayaqua/Pack.c, packet definitions/parsers in
Mayaqua/TcpIp.c, and IPC in Cedar/IPsec_IPC.c in this checkout; the requested
Cedar/Pack.c, Cedar/Packet.c and Cedar/IPC.c paths do not exist.

## Modules and ownership

* core-protocol: bounded PACK, upstream-compatible SHA-0 authentication,
  HTTP signature/login, welcome negotiation and TCP Ethernet framing.
* core-network: IPv4 validation, checksums, routes and UDP helpers.
* core-l2: Ethernet II, ARP cache, virtual endpoint and bounded ARP waiting.
* core-dhcp: DHCP packet codec and timed DISCOVER/OFFER/REQUEST/ACK exchange.
* core-security: system trust plus explicit SHA-256 leaf certificate pins.
* app: Compose UI, DataStore profile, Keystore-encrypted password, physical
  Network tracking, foreground VpnService and TUN lifecycle.
* integration: host runner sharing the production protocol/L2/DHCP modules,
  stock-server setup and a device acceptance procedure.

## Packet flow and bootstrap

Android TUN carries IP packets. SoftEther transports Ethernet frames, including
ARP and DHCP. There is no direct substitution of TUN for TAP.

Outbound: TUN IPv4 -> validate length/source/MTU -> longest-prefix next hop
-> ARP cache or bounded resolution queue -> Ethernet II -> native batch
framing -> TLS -> stock hub. Inbound: TLS -> bounded native framing ->
Ethernet destination/type validation -> ARP/DHCP consumed internally, or
validated IPv4 addressed to the leased endpoint -> TUN write.

Initialize the socket descriptor without connecting (TCP_NODELAY creates the
Android SocketImpl), then protect and bind the physical socket before connect.
Android's protect(Socket) reads the descriptor directly and does not create it.
Authenticate before
starting DHCP. A secure-random locally administered MAC is persisted per
profile. DHCP runs entirely over L2 while no TUN exists. Validate ACK address,
contiguous mask, gateway/routes, DNS and lease before establishing TUN with
full IPv4 route and supplied DNS. IPv6 is blocked by omitting IPv6 addresses,
routes and allowFamily(AF_INET6); never claim IPv6 support.

One coroutine owns each receive/transmit loop. Channels have explicit bounds.
Session close interrupts blocking socket I/O; TUN uses nonblocking descriptor
I/O and polling so cancellation does not depend on a blocking TUN read.
All resources are enclosed by try/finally, including setup failures. Connected
is published only after authenticated session, DHCP, TUN and forwarding jobs.

## Reconnection and security boundaries

An explicit phase enum is exposed as StateFlow. A single controller job owns
attempts, closes the transport on underlying Network loss/change and retries
transient failures using capped exponential backoff plus secure-random jitter.
The network monitor uses ordered onCapabilitiesChanged snapshots; it does
not re-query ConnectivityManager inside callbacks or change its physical
selection merely because the VPN becomes the default network. Equal-priority
candidates preserve the existing selection; validated networks are preferred.
User disconnect/revocation cancels that job immediately. Each new attempt
gets a fresh session, DHCP and ARP cache. DHCP leases are renewed; expiry or
configuration changes cause controlled session/TUN replacement.

Default TLS uses system CA validation and HTTPS endpoint identification.
Explicit leaf certificate pin mode validates the exact SHA-256 fingerprint
and certificate validity; the pin is the configured identity, clearly shown
in UI. No trust-all manager or TLS-to-plaintext switch exists. TLS 1.2/1.3 only.
Remote lengths are bounded before allocation. Log export contains only local
phase names, numeric protocol error codes and counters. Passwords are never
placed in intents, saved UI state, backups or diagnostics.

Initial scope: one direct TCP/TLS channel, IPv4 full tunnel, password and
anonymous authentication. Compression, RC4, UDP acceleration, redirects,
IPv6 and multi-channel transport are explicitly deferred and rejected if
unexpectedly negotiated. Production status requires the device acceptance
matrix; a successful build alone cannot establish that status.
