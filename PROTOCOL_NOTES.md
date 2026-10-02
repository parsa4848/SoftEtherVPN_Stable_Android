# Auditable SoftEther protocol notes

## Extension audit and implementation plan, 2026-10-02

Read the pinned local Stable source before extending the client: Protocol.c/h,
Connection.c/h, Session.c/h, UdpAccel.c/h, Cedar.h and Mayaqua Network.c/h.
MAX_TCP_CONNECTION is 32; directions are BOTH=0, SERVER_TO_CLIENT=1,
CLIENT_TO_SERVER=2. ClientUploadAuth sends the requested `max_connection`;
ClientConnect respects the server limit. ClientAdditionalConnect sends the
signature, downloads Hello, calls ClientUploadAuth2/PackAdditionalConnect
(`method=additional_connect`, 20-byte `session_key`, PackAddClientVersion),
then checks error and direction. Errors 13/14 expire the logical session.
ConnectionSend schedules whole blocks using eligible socket queue pressure.

UDP acceleration uses the exact ClientUploadAuth/PackWelcome fields.
UdpAccel.c v2 is a 12-byte IV, encrypted big-endian cookie/two ticks/uint16
payload length/byte flag/payload/padding, then a 16-byte ChaCha20-Poly1305 tag.
The 128-byte advertised directional key uses its first 32 bytes for AEAD.
V1 uses SHA1(common-key || IV) and RC4 with a 20-byte zero trailer.
UdpAccelIsSendReady requires a recent echoed local tick and 10 seconds of
continuous reception; failure leaves the native reliable transport alive.

Network.c RUDPNewSession derives keys with SHA1 and WriteBufStr (a uint32
length including one, without a transmitted NUL), and seeds the stream with
the disconnect magic. RUDPSendSegmentNow uses signature/20-byte IV/RC4 body,
ticks, cumulative ACK, up to 64 selective ACKs, sequence, <=512 payload bytes
and 1..255 padding bytes. The signature is SHA1(key || IV || ciphertext)
XOR SHA1(lowercase service name `softether_vpn`). The send window is 64;
retries start at 200ms and cap at 4792ms, with echoed-tick RTT adjustment.
DNS queries use the upstream 37-byte wrapper; responses use the 42-byte
wrapper. Transaction IDs are opaque bytes (C writes a native ushort), while
payload lengths and protocol integers are big-endian. Direct DNS bypasses
NewRUDPClientNatT discovery and targets the server IPv4 address on UDP/53.
TLS still runs over the reconstructed stream. Without UDP recovery, server
and client restrict R-UDP to one connection.

Authoritative checkout: SoftEtherVPN/SoftEtherVPN_Stable,
`ed17437af9719ac66acab30faa29e375d613c35f`, release 4.44 build 9807.
Protocol.c SHA-256:
`e2cff892d23b56e1bc9e5981bb5080e774b9cf02d8c748fb0f2aea3fba5a1593`.
[Pinned upstream source](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/tree/ed17437af9719ac66acab30faa29e375d613c35f).

The reported phone test uses Stable 4.41 build 9787. Its tagged Protocol.c was
also checked: ServerDownloadSignature accepts the same compact native token,
and its login uses the same single-TCP negotiation fields. This source check
does not establish a successful 4.41 server session.
[4.41 source](https://github.com/SoftEtherVPN/SoftEtherVPN_Stable/blob/v4.41-9787-rtm/src/Cedar/Protocol.c).

## Complete path reviewed

`vpncsvc.c:StartProcess` -> `CtStartClient` -> `CiConnect` in Client.c
-> `VLanGetPacketAdapter` -> `NewClientSessionEx` in Session.c
-> `ClientConnect` in Protocol.c -> `ClientConnectToServer` (TLS)
-> `ClientUploadSignature` -> `ClientDownloadHello` -> certificate check
-> `ClientUploadAuth` -> welcome/session key/options -> TCP connection
-> SessionMain packet-adapter callbacks -> ConnectionSend/ConnectionReceive
-> `VLanUnix.c` TAP read/write. Android replaces the adapter boundary, not
the entire Unix service or server.

Protocol.h, Client.h, Session.h, Connection.h, VLan.c/Unix.c, UdpAccel.c/h,
GlobalConst.h, Mayaqua Pack/Memory/Network/Encrypt/TcpIp/Unix interfaces,
IPsec_IPC.c/h, vpncsvc.c and Linux makefiles were inspected. In this Stable
checkout PACK and packet code live in Mayaqua; IPC is called IPsec_IPC.

| Kotlin implementation | Upstream reference |
|---|---|
| SoftEtherTlsTransport.connect | Protocol.c ClientConnectToServer / ClientCheckServerCert; Android protect/bind is the platform addition |
| SoftEtherSession.connect | Protocol.c ClientConnect / ClientDownloadHello / GetHello / ParseWelcomeFromPack / GetSessionKeyFromPack |
| SoftEtherConnectionPool | Protocol.c ClientAdditionalConnect / ClientAdditionalConnectToServer; Connection.c ConnectionSend / ConnectionReceive |
| SoftEtherSession.attachAdditional | Protocol.c ClientUploadAuth2 / PackAdditionalConnect / PackAddClientVersion / ServerAccept |
| UdpAccelerationOffer | Protocol.c ClientUploadAuth / PackWelcome / ClientConnect; UdpAccel.c NewUdpAccel / UdpAccelInitClient |
| UdpAccelerationCodec / Engine | UdpAccel.c UdpAccelSend / UdpAccelCalcKey / UdpAccelProcessRecvPacket / UdpAccelPoll / UdpAccelIsSendReady / UdpAccelCalcMss |
| RudpKeys / PacketCodec / Session | Mayaqua/Network.c RUDPNewSession / RUDPSendSegmentNow / RUDPCheckSignOfRecvPacket / RUDPProcessRecvPacket / RUDPRecvProc / RUDPInterruptProc |
| RudpDnsCodec / Transport | Network.c RUDP_PROTOCOL_DNS in RUDPSendPacket / RUDPMainThread; NewRUDPClientDirect / ConnectThreadForOverDnsOrIcmp |
| TransportSelector / StreamTlsTransport | Direct UDP53 establishes a stream before the existing TLS and ClientConnect path; no NewRUDPClientNatT discovery |
| Signature POST | Protocol.c ClientUploadSignature / ServerDownloadSignature; Mayaqua/Network.h HTTP_VPN_TARGET2 / HTTP_VPN_TARGET_POSTDATA |
| SoftEtherHttp | Mayaqua/Network.c HttpClientSend / HttpClientRecv / PostHttp |
| SoftEtherPackCodec | Mayaqua/Pack.c WritePack / WriteElement / WriteValue / ReadPack / ReadElement / ReadValue |
| PACK name lengths and integers | Mayaqua/Memory.c WriteBufStr / ReadBufStr / WriteBufInt / WriteBufInt64 |
| SoftEtherAuthenticator | Cedar/Account.c HashPassword; Cedar/Sam.c SecurePassword; Protocol.c PackLoginWithPassword / PackLoginWithAnonymous / ClientUploadAuth |
| Sha0.digest | Mayaqua/Encrypt.c Hash(true) -> Internal_SHA0 -> MY_SHA0_Transform/update/final |
| Login metadata | Protocol.c PackAddClientVersion / CreateNodeInfo; Admin.c OutRpcNodeInfo; Mayaqua/Pack.c PackAddIp32 / PackAddIpEx2 |
| SoftEtherDataChannel | Cedar/Connection.c TCP send FIFO, receive modes 0–4, SendKeepAlive; Cedar.h KEEP_ALIVE_MAGIC/MAX_KEEPALIVE_SIZE/MAX_PACKET_SIZE |
| VirtualEthernetEndpoint | Cedar/Session.c PACKET_ADAPTER callbacks; IPsec_IPC.c IPCSendIPv4 / IPCSendIPv4Unicast / IPCProcessArp |
| DhcpClient / DhcpCodec | IPsec_IPC.c IPCDhcpAllocateIPEx / IPCSendDhcpRequest / IPCBuildDhcpRequestOptions; Mayaqua/TcpIp.c DHCP parser and classless route helpers |
| Error mapping | Cedar/Cedar.h ERR_*; Protocol.c GetErrorFromPack |

## Wire invariants

PACK starts with a big-endian uint32 element count. Each element has a
big-endian name length **including one**, then only the actual name bytes
(no NUL), uint32 type, uint32 value count, and values. Types 0/1/2/3/4 mean
uint32/data/string/Unicode/uint64. DATA and STR lengths count the transmitted
bytes. UNISTR length includes its transmitted UTF-8 trailing NUL. Names are
case-insensitive and sorted. Integer fields are big-endian on the wire.

Node metadata is an exception at the value level: CreateNodeInfo stores
network-order versions/ports and OutRpcNodeInfo applies LittleEndian32,
so their uint32 values must be byte-reversed before PACK encoding. IPv4
PackAddIp32 values likewise contain reversed address octets. Ordinary
`client_ver`, `version`, `timeout`, `max_connection` etc. are not reversed.

Signature uses `POST /vpnsvc/connect.cgi`, image/jpeg, and the exact
`VPNCONNECT` token explicitly accepted by ServerDownloadSignature. No
watermark image was copied. Server hello is HTTP 200 application/octet-stream
PACK with a 20-byte random challenge. Login uses `/vpnsvc/vpn.cgi` and a
random `pencore` data value as HttpClientSend does. Welcome terminates HTTP
negotiation; the same TLS socket carries binary data thereafter.

Password response is **SHA-0**, not Java SHA-1:

`SHA0(SHA0(UTF8(password) || ASCII_UPPER(username)) || challenge[20])`.

This follows HashPassword and SecurePassword exactly; the SHA1_SIZE constant
names the 20-byte size, not the algorithm. SHA-0 exists only for SoftEther
compatibility inside authenticated TLS. ASCII usernames are enforced;
passwords use UTF-8. Plain-password and certificate authentication are not
advertised. Anonymous authtype=0 is supported; password authtype=1.

Negotiation requests protocol=0, max_connection=requested (1..32), encryption=true,
compression=false, RC4=false, half_connection=false, qos=false,
UDP acceleration follows the profile offer and UDP recovery=false. Reject unexpected negotiation,
including TLS-to-plaintext switching. Preserve the 20-byte session key and
uint32 key in private session state; wipe on close. No debug toString exposes
key material. Additional connections send only the existing session key and
client version metadata, after TLS identity and native signature/hello checks.
The negotiated count clamps the requested count; server errors 13/14 rebuild
the session. A failed secondary is replaced with bounded backoff.

Data: uint32 batch count, then per block uint32 length plus Ethernet bytes.
Keepalive: `ffffffff`, uint32 length, up to 512 bytes. Empty block/batch and
zero-length keepalive handling follows receive modes. Locally cap frames at
1600 bytes, batch count at 4096, HTTP headers at 16 KiB and PACK at 1 MiB.
These tighter client resource limits intentionally reject oversized responses.
Keepalive interval is one-third of negotiated timeout. UDP acceleration's
native keepalive payload uses `NATT_MY_PORT` followed by big-endian uint16.
Discovery uses the stock hashed NAT-T hostname and UDP5004 `B` request;
it is separate from direct VPN-over-DNS, which contacts only the server IPv4.
Session shutdown closes all owned underlays; the server's normal
connection-loss/timeout path releases the session.

Acceleration advertises encrypted v2 when the platform provider supplies
ChaCha20-Poly1305 and otherwise v1. Android's provider documents v2 from
API28; API26/27 can use the stock v1 codec. A server declining UDP or supplying
incomplete/unsupported parameters leaves TCP working. Plaintext acceleration
and compressed packet flags are rejected. Endpoint changes require valid
packet crypto/cookie and a newer peer tick. Lost readiness falls back to TCP
and keepalive probes continue for recovery.
[Android cipher support](https://developer.android.com/reference/javax/crypto/Cipher).

The explicit DNS transport requires server `EnableVpnOverDns=true`. It does
not invoke DNS resolvers to carry protocol packets. Auto chooses TCP and
does not race transports. Bulk/recovery are not advertised, so upstream forces
one connection for R-UDP; the requested TCP count remains visible separately.
DNS transaction IDs can refer to the latest query rather than one outstanding
request; acceptance relies on signed R-UDP packets, not ID equality.

## MVPN and secondary references

Stable Protocol.c line 7444 gates `/mvpn` dispatch behind `if (false) // TODO`.
MvpnDoAccept includes WebSocket nonce/auth negotiation, L3 DHCP allocation,
IPCSendIPv4, heartbeat and L2/L3 packet-type dispatch. Useful architectural
ideas, but not a supported stock Stable entry point. The client never calls it.

[Minimum VPN Client](https://github.com/kittoku/Minimum-VPN-Client-for-SoftEther-VPN)
was inspected at `289fa2d4afb6ff4de8e597a175b75affd8fb8889`:
Apache-2.0; password + SecureNAT assumptions, shared mutable bridge, assertion
parsers, socket protection after connect/TLS and no explicit HTTPS endpoint
identification in TCPTerminal. It uses SecureRandom. Its SHA-0 padding formula
adds an unnecessary block at some boundary lengths, motivating C-derived
boundary vectors. No source from this project is bundled or copied.

[Developer Edition](https://github.com/SoftEtherVPN/SoftEtherVPN)
was inspected at `40120e17233f26f1cd196b9239b129e51805e470` for native
Connection.c framing, Protocol.c and IPC.c helper behavior. Its repository
has no iOS submodule in the inspected .gitmodules; historical iOS integration
and [Android/iOS discussion #1624](https://github.com/SoftEtherVPN/SoftEtherVPN/issues/1624)
are secondary context, never the Stable wire authority. No iOS/Swift source
was adapted.

## Regression procedure

Regenerate C fixtures with tools/upstream_vectors.py and
tools/transport_vectors.py after explicitly
reviewing an upstream revision change. Run all tests, compare signature/login
and native frames with the official desktop client, then run the host and
device acceptance matrices. Do not change hashes, field names, byte order,
negotiation defaults or framing solely to satisfy a guessed packet trace.
The transport harness executes extracted C writers for v1/v2 acceleration,
R-UDP signatures, key derivation and DNS query/response wrappers. Fixed random
values are confined to the test harness. Its current Windows build uses clang
and Git for Windows' local OpenSSL DLL; neither is an APK dependency.
