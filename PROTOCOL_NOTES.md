# Auditable SoftEther protocol notes

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

Negotiation requests protocol=0, max_connection=1, encryption=true,
compression=false, RC4=false, half_connection=false, qos=false,
UDP acceleration=false and UDP recovery=false. Reject unexpected negotiation,
including TLS-to-plaintext switching. Preserve the 20-byte session key and
uint32 key in private session state; wipe on close. No debug toString exposes
key material. Extra connection/session-key use is deferred.

Data: uint32 batch count, then per block uint32 length plus Ethernet bytes.
Keepalive: `ffffffff`, uint32 length, up to 512 bytes. Empty block/batch and
zero-length keepalive handling follows receive modes. Locally cap frames at
1600 bytes, batch count at 4096, HTTP headers at 16 KiB and PACK at 1 MiB.
These tighter client resource limits intentionally reject oversized responses.
Keepalive interval is one-third of negotiated timeout; no UDP transport
exists in the first milestone. Session shutdown closes TCP; the server's
normal connection-loss path releases the session.

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

Regenerate C fixtures with tools/upstream_vectors.py after explicitly
reviewing an upstream revision change. Run all tests, compare signature/login
and native frames with the official desktop client, then run the host and
device acceptance matrices. Do not change hashes, field names, byte order,
negotiation defaults or framing solely to satisfy a guessed packet trace.
