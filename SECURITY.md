# Security boundaries

The app is an initial IPv4 implementation pending real-device acceptance,
external review and sustained reliability/performance testing.

## Transport identity

Default uses Android system CA validation, HTTPS endpoint identification and
TLS 1.2/1.3. Password authentication occurs only after TLS succeeds. Explicit
pin mode accepts **only the exact SHA-256 leaf certificate fingerprint**,
checks its validity dates and uses that certificate as the configured server
identity. It intentionally supports self-signed/private certificates and is
clearly labeled. Obtain pins through an authenticated administrator channel;
there is no trust-on-first-use or accept-all fallback. Certificate rotation
requires an explicit new pin. Client certificate authentication is deferred.

Native password challenge compatibility requires SHA-0. It is confined to
the SoftEther authentication flow; new storage/pinning uses AES-GCM/SHA-256.
No password-derived material or session keys are logged. Java/Compose String
copies of entered passwords cannot be reliably erased; passwords are masked,
excluded from saved state and cleared after saving. Temporary mutable secret
buffers are wiped. FLAG_SECURE blocks screenshots and recent-task captures.

Additional TLS sockets validate the same server certificate as the primary
and authenticate attachment using its private session key. The key is copied
under a short state lock and temporary PACK buffers are wiped. R-UDP/DNS
always carries TLS; its legacy SHA-1/RC4 packet signing/encryption is the stock
compatibility layer and cannot replace TLS server identity or confidentiality.
Acceleration v2 uses platform ChaCha20-Poly1305; v1 preserves upstream's RC4,
cookie and zero-trailer validation, which does not offer modern AEAD security.
Plaintext acceleration is not accepted. Key-bearing objects have no diagnostic
data-class output, and all random key/IV/transaction values use SecureRandom.

## Persistence

Non-secret settings and stable random client identity use Preferences DataStore.
Passwords use randomized AES-256-GCM with Android Keystore keys and profile
identity as authenticated data. Keys are non-exportable through Android's
Keystore API; hardware backing depends on device capabilities. Authentication
is not required to use the key so foreground reconnect can work while locked.
No plaintext password is persisted or placed in intents. Cloud backup and
device transfer are excluded. Reinstall/key loss requires password re-entry.

## OS routing

Every primary/additional TCP, acceleration UDP and R-UDP UDP socket's
descriptor is initialized before protection, without connecting
or binding a local address. The socket is protected before connect and explicitly bound to a non-VPN
underlying Network. Protection failure is a connection failure. DNS resolution
of the transport hostname runs on that physical Network. This unavoidable
server bootstrap resolution is distinct from application DNS, which uses DHCP
DNS inside the full IPv4 route after TUN exists. Optional custom DNS is an
explicit user choice; no arbitrary public resolver is selected automatically.
Optional acceleration NAT discovery resolves the upstream NAT-T hostname on
the physical Network and uses its already protected UDP socket. R-UDP/DNS
targets only the configured server IPv4/UDP53. Protection/bind failures close
the socket immediately. Network migration creates fresh keys and mappings.

IPv6 is blocked while the VPN interface is active by not configuring or
allowing that address family. IPv6 tunneling is not implemented. There is
**no kill switch** during connection/reconnection or after disconnect. At those
times traffic may use the physical network. Always-on startup/lockdown has not
been implemented or advertised. Android permission revocation closes both
TUN and transport and cancels reconnect.

## Untrusted packet input

Enforce PACK/HTTP and native frame bounds before allocation. Reject duplicate
PACK/header fields, unknown types, truncated values and trailing data. Validate
Ethernet types, destination MAC, ARP hardware/protocol/opcode/sizes/source MAC,
IPv4 lengths/header/checksum/MTU, UDP checksums/lengths and DHCP option lengths,
transaction ID/client MAC/server selection/lease times/routes/DNS. DHCP is a
trusted-network configuration protocol, not authenticated against hostile hub
participants. On-link ARP can also be attacked by other hub members; the client
only learns relevant addressed requests and solicited replies. Strong hub
isolation/server policy remains important.

Bound packet channels to 128 frames, DHCP renewal replies to 16, ARP pending
destinations to 64, total pending packets to 128 and per-destination packets
to 8. ARP cache expires and has at most 256 entries. No per-packet coroutine
creation, GlobalScope or unbounded retransmission queues. Blocking TLS read/
write is interrupted by closing the raw socket at cancellation; nonblocking
TUN uses cancellable poll intervals. Stalled tunnel writes have a watchdog.
Pool writers are bounded to 16 frames per connection, at most 32 sockets.
R-UDP uses 64-segment send/reassembly windows, 512-byte segments and bounded
64 KiB FIFOs/128-segment stream queues. Datagram sizes and ACK counts are
validated before allocation; corrupt packets do not enlarge those windows.

## Diagnostics and release gate

Diagnostics use an allowlisted category interface, retain at most 200 events
and export only app version, phases, failure/operation enums, numeric OS/server
error codes and counters. Raw exception text is never exported. No sensitive payload dump,
credentials, hashes, TLS certificates/keys or session keys are emitted.
Debug APKs must be kept separate from signed production distribution.

Before production: finish the stock-server/phone acceptance matrix, verify
API 26 and current Android foreground service behavior, add connection and
packet soak/fault-injection tests, evaluate OEM power management, perform a
security audit, and choose a deliberate always-on/kill-switch product policy.
