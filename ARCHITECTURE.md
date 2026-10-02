# Architecture decision: Kotlin native client and virtual Ethernet endpoint

Status: implementation selected; device acceptance remains a separate gate.

## 2026-10-02 extension design (before implementation)

The baseline is commit `a4b8fb8`, version 0.1.1. The unmodified debug APK
builds with cached dependencies. Fresh host tests and its preserved APK are
recorded in TEST_RESULTS.md and `dist/baseline/`. No device is attached.

Keep the PACK/HTTP/authentication, virtual Ethernet, DHCP, TUN, Keystore and
physical-network controller. Extend the existing stream transport interface:

* Profile preferences default to one TCP connection, acceleration disabled,
  TCP transport. Old DataStore entries retain their credentials and identity.
* Initial login negotiates the connection limit. A session-owned pool attaches
  protected TLS sockets with `additional_connect` and the existing session
  key. Bounded per-socket writers schedule complete Ethernet records; readers
  merge into the existing bounded input channel. Individual failures remove
  sockets; a single replenishment job retries with backoff. Errors 13/14
  invalidate the session. No extra DHCP or TUN exists.
* Optional protected UDP acceleration is prepared before login. A separate
  codec and session worker handle negotiation, authenticated packets,
  endpoint learning, keepalive and upstream readiness. TCP stays available.
* R-UDP/DNS supplies a bounded reliable byte stream over a protected IPv4
  UDP socket directed to the configured server on port 53. TLS using
  SSLEngine wraps that stream with the same certificate policy before the
  unchanged native handshake. Bulk and UDP recovery are not advertised;
  upstream consequently restricts this session to one connection.
* Auto initially chooses TCP, preserving the reliable baseline. Explicit
  UDP/53 never falls back to TCP. Network changes close the entire attempt
  and rebuild sockets, keys, NAT mappings, DHCP and TUN as before.
* Counters are sampled once per second; workers never publish UI per packet.
  Every worker is a child of the attempt scope and every socket is owned
  before setup can block. Queues and retransmission/reassembly windows are
  bounded. Disconnect interrupts socket I/O and cancels workers.

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
  HTTP signature/login, welcome negotiation, connection pool, UDP acceleration
  and reliable UDP/DNS stream/packet codecs.
* core-network: IPv4 validation, checksums, routes and UDP helpers.
* core-l2: Ethernet II, ARP cache, virtual endpoint and bounded ARP waiting.
* core-dhcp: DHCP packet codec and timed DISCOVER/OFFER/REQUEST/ACK exchange.
* core-security: system trust plus explicit SHA-256 leaf certificate pins,
  SSLEngine TLS over the reliable UDP stream.
* app: Compose UI, DataStore profile, Keystore-encrypted password, physical
  Network tracking, foreground VpnService and TUN lifecycle.
* integration: host runner sharing the production protocol/L2/DHCP modules,
  stock-server setup and a device acceptance procedure.

## Packet flow and bootstrap

Android TUN carries IP packets. SoftEther transports Ethernet frames, including
ARP and DHCP. There is no direct substitution of TUN for TAP.

Outbound: TUN IPv4 -> validate length/source/MTU -> longest-prefix next hop
-> ARP cache or bounded resolution queue -> Ethernet II -> session scheduler.
The scheduler selects authenticated UDP acceleration when ready, otherwise a
pool writer sends the complete native record over TLS. TLS may use TCP or the
explicit reliable UDP/DNS stream. Inbound: UDP acceleration or native framing ->
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

The primary and all additional connections share one authentication/session,
one L2/DHCP endpoint and one TUN. The pool uses bounded 16-frame writer queues,
queue pressure and round-robin ties without per-packet sorting. A single
manager creates additional connections; an independent watchdog closes stalled
writes even during a secondary handshake. Resource publication/collection uses
short state locks; socket closure and network setup occur outside those locks.

UDP acceleration has one socket worker and an optional NAT discovery child.
Its 128-frame queue falls back to the pool when unavailable/full. Authenticated
newer peer ticks update the endpoint. Native keepalives exchange NAT ports.
Readiness follows upstream's 10-second stable reception requirement and recent
echo timeout; Active also requires successfully sent and received data bytes.

R-UDP has one reliability/socket worker, 64-segment windows with 512-byte
segments, 64 KiB send/receive FIFOs, and 128-segment stream queues. TLS has
three fixed 64 KiB buffers and a 32 KiB output buffer, matching the baseline
record flushing. Backpressure bounds memory rather than growing
retransmission or reassembly queues. Socket closure interrupts the adapters;
cancellation joins children through the existing attempt scope. Network changes
recreate the entire attempt, including UDP keys, endpoints and NAT state.

Compression, native fast RC4, redirects, IPv6, bulk R-UDP, UDP recovery,
VPN Azure and NAT-T transport discovery remain unsupported. Legacy RC4 is
used only where stock R-UDP and acceleration v1 require it. TLS always wraps
R-UDP. Production status requires the device acceptance matrix.
