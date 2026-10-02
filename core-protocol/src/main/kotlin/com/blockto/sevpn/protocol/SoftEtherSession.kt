package com.blockto.sevpn.protocol

import java.io.*
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Locale

interface SoftEtherTransport : Closeable {
    val peerCertificate: ByteArray? get() = null
    val type: TransportType get() = TransportType.TCP
    val input: InputStream
    val output: OutputStream
    val localAddress: java.net.InetSocketAddress? get() = null
    val remoteAddress: java.net.InetSocketAddress? get() = null
    fun setReadTimeout(milliseconds: Int)
}

class SocketTransport(private val socket: Socket) : SoftEtherTransport {
    override val peerCertificate: ByteArray? get() = (socket as? javax.net.ssl.SSLSocket)?.session?.peerCertificates?.firstOrNull()?.encoded
    override val input = BufferedInputStream(socket.getInputStream(), 32 * 1024)
    override val output = BufferedOutputStream(socket.getOutputStream(), 32 * 1024)
    override val localAddress get() = socket.localSocketAddress as? java.net.InetSocketAddress
    override val remoteAddress get() = socket.remoteSocketAddress as? java.net.InetSocketAddress
    override fun setReadTimeout(milliseconds: Int) { socket.soTimeout = milliseconds }
    override fun close() { socket.close() }
}

class SoftEtherServerException(val code: Int) : IOException(when (code) {
    7 -> "Server does not support this authentication method"
    8 -> "Virtual Hub not found"
    9 -> "Username or password rejected"
    10 -> "Virtual Hub is offline"
    12 -> "Server policy denied access"
    13 -> "SoftEther session expired"
    14 -> "SoftEther session is no longer valid"
    15, 16, 20 -> "Server connection or session limit reached"
    else -> "SoftEther server error $code"
})

/** Header parser reads exactly through CRLFCRLF; never swallows following data. */
class SoftEtherHttp(private val transport: SoftEtherTransport, private val host: String) {
    init { require(host.isNotBlank() && host.all { it.code in 33..126 } && '\r' !in host && '\n' !in host) }
    fun post(path: String, contentType: String, body: ByteArray) {
        require(body.size <= SoftEtherPackCodec.MAX_SIZE)
        val header = "POST $path HTTP/1.1\r\nHost: $host\r\nContent-Type: $contentType\r\nContent-Length: ${body.size}\r\nConnection: Keep-Alive\r\nKeep-Alive: timeout=15; max=19\r\n\r\n"
        transport.output.write(header.toByteArray(Charsets.US_ASCII)); transport.output.write(body); transport.output.flush()
    }
    fun receivePack(): Pack {
        val h = ByteArrayOutputStream()
        var tail = 0
        while (true) {
            val c = transport.input.read()
            if (c < 0) throw EOFException("Server closed during HTTP handshake")
            if (h.size() >= 16 * 1024) throw ProtocolException("HTTP header exceeds bounds")
            h.write(c); tail = (tail shl 8) or c
            if (tail == 0x0d0a0d0a) break
        }
        val lines = String(h.toByteArray(), Charsets.ISO_8859_1).split("\r\n")
        if (!lines[0].startsWith("HTTP/1.1 200 ")) throw ProtocolException("Server did not return SoftEther HTTP success")
        val fields = mutableMapOf<String, String>()
        for (line in lines.drop(1).filter { it.isNotEmpty() }) {
            val colon = line.indexOf(':')
            if (colon < 1) throw ProtocolException("Malformed HTTP header")
            val key = line.substring(0, colon).lowercase(Locale.ROOT)
            if (fields.put(key, line.substring(colon + 1).trim()) != null) throw ProtocolException("Duplicate HTTP header")
        }
        if (fields.containsKey("transfer-encoding")) throw ProtocolException("Unsupported HTTP encoding")
        if (fields["content-type"]?.lowercase(Locale.ROOT) != "application/octet-stream") throw ProtocolException("Server is not speaking SoftEther PACK")
        val size = fields["content-length"]?.toIntOrNull() ?: throw ProtocolException("Missing HTTP content length")
        if (size !in 4..SoftEtherPackCodec.MAX_SIZE) throw ProtocolException("HTTP content size outside bounds")
        val bytes = ByteArray(size)
        DataInputStream(transport.input).readFully(bytes)
        return try { SoftEtherPackCodec.decode(bytes) } finally { bytes.fill(0) }
    }
}

class SoftEtherSession private constructor(
    private val transport: SoftEtherTransport,
    val sessionName: String,
    val timeoutMs: Int,
    private val sessionKey: ByteArray,
    private var sessionKey32: Long,
    val requestedTcpConnections: Int,
    val negotiatedMaxConnections: Int,
    val udpAcceleration: UdpAccelerationConfig?
) : Closeable {
    val channel = SoftEtherDataChannel(transport)
    val primaryTransport get() = transport
    private val keyLock = Any()
    private var closed = false
    fun attachAdditional(next: SoftEtherTransport, host: String): AdditionalConnection {
        var hello: Pack? = null; var reply: Pack? = null; var pack: Pack? = null
        try {
            val identity = transport.peerCertificate
            if (identity != null && !java.security.MessageDigest.isEqual(identity, next.peerCertificate))
                throw javax.net.ssl.SSLPeerUnverifiedException("Additional connection certificate changed")
            val http = SoftEtherHttp(next, host)
            next.setReadTimeout(15_000)
            http.post("/vpnsvc/connect.cgi", "image/jpeg", "VPNCONNECT".toByteArray(Charsets.US_ASCII))
            hello = http.receivePack(); checkError(hello)
            if (hello.data("random")?.size != 20 || hello.str("hello") == null) throw ProtocolException("Invalid additional connection hello")
            pack = synchronized(keyLock) {
                if (closed) throw IOException("Session closed")
                Pack().str("method", "additional_connect").data("session_key", sessionKey.copyOf())
                    .str("client_str", "SEVPN Android").uint("client_ver", 444).uint("client_build", 9807)
            }
            val encoded = SoftEtherPackCodec.encode(pack)
            try { http.post("/vpnsvc/vpn.cgi", "application/octet-stream", encoded) } finally { encoded.fill(0); pack.wipe() }
            reply = http.receivePack(); checkError(reply)
            val direction = reply.int("direction")
            if (direction !in 0..2) throw ProtocolException("Invalid additional connection direction")
            synchronized(keyLock) { if (closed) throw IOException("Session closed") }
            next.setReadTimeout(timeoutMs)
            return AdditionalConnection(next, direction.toInt())
        } catch (e: Throwable) { runCatching { next.close() }; throw e }
        finally { hello?.wipe(); reply?.wipe(); pack?.wipe() }
    }
    override fun close() {
        synchronized(keyLock) { closed = true; sessionKey.fill(0); sessionKey32 = 0 }
        udpAcceleration?.close()
        transport.close()
    }
    companion object {
        fun connect(transport: SoftEtherTransport, host: String, hub: String, username: String,
                    password: CharArray?, machineId: ByteArray, options: SessionOptions = SessionOptions(), authenticating: () -> Unit = {}): SoftEtherSession {
            require(machineId.size == 20 && hub.toByteArray().size in 1..255 && username.toByteArray().size in 1..255)
            val http = SoftEtherHttp(transport, host)
            var hello: Pack? = null
            var login: Pack? = null
            var welcome: Pack? = null
            try {
                transport.setReadTimeout(15_000)
                // ServerDownloadSignature explicitly accepts HTTP_VPN_TARGET_POSTDATA.
                http.post("/vpnsvc/connect.cgi", "image/jpeg", "VPNCONNECT".toByteArray(Charsets.US_ASCII))
                hello = http.receivePack()
                checkError(hello)
                val random = hello.data("random") ?: throw ProtocolException("Missing hello challenge")
                if (random.size != 20 || hello.str("hello") == null) throw ProtocolException("Invalid SoftEther hello")
                authenticating()
                login = SoftEtherAuthenticator.login(hub, username, password, random)
                login.str("client_str", "SEVPN Android").uint("client_ver", 444).uint("client_build", 9807)
                    .str("hello", "SEVPN Android").uint("version", 444).uint("build", 9807).uint("client_id", 0)
                    .uint("protocol", 0).uint("max_connection", options.requestedTcpConnections.toLong()).bool("use_encrypt", true)
                    .bool("use_compress", false).bool("use_fast_rc4", false).bool("half_connection", false)
                    .bool("qos", false).bool("require_bridge_routing_mode", false).bool("require_monitor_mode", false)
                    .bool("support_udp_recovery", false)
                    .bool("support_bulk_on_rudp", false).bool("support_hmac_on_bulk_of_rudp", false)
                    .data("unique_id", machineId.copyOf()).data("UniqueId", machineId.copyOf(16))
                    .str("ClientProductName", "SEVPN Android").str("ClientOsName", "Android")
                    .str("ClientOsVer", "26+").str("ClientHostname", "android-sevpn").str("ServerHostname", host)
                    .str("ServerProductName", hello.str("hello")!!).str("HubName", hub)
                    .uint("ClientProductVer", metadataInt(444)).uint("ClientProductBuild", metadataInt(9807))
                    .uint("ServerProductVer", metadataInt(hello.int("version"))).uint("ServerProductBuild", metadataInt(hello.int("build")))
                addAddress(login, "ClientIpAddress", "ClientIpAddress6", transport.localAddress)
                addAddress(login, "ServerIpAddress", "ServerIpAddress6", transport.remoteAddress)
                login.uint("ClientPort", metadataInt((transport.localAddress?.port ?: 0).toLong()))
                    .uint("ServerPort2", metadataInt((transport.remoteAddress?.port ?: 0).toLong()))
                    .str("ClientOsProductId", "").str("ProxyHostname", "").uint("ProxyPort", 0)
                addAddress(login, "ProxyIpAddress", "ProxyIpAddress6", null)
                options.udpAcceleration?.advertise(login)
                val randomPad = ByteArray(SecureRandom().nextInt(1000)).also { SecureRandom().nextBytes(it) }
                login.data("pencore", randomPad)
                val auth = SoftEtherPackCodec.encode(login)
                try { http.post("/vpnsvc/vpn.cgi", "application/octet-stream", auth) } finally { auth.fill(0); login.wipe() }
                welcome = http.receivePack()
                checkError(welcome)
                if (welcome.bool("Redirect")) throw ProtocolException("Cluster redirects are not supported in this version")
                if (!welcome.bool("use_encrypt") || welcome.bool("use_compress") || welcome.bool("use_fast_rc4") || welcome.bool("half_connection") || welcome.bool("qos"))
                    throw ProtocolException("Server negotiated an unsupported or insecure transport")
                val maxConnections = welcome.int("max_connection")
                if (maxConnections !in 1..32) throw ProtocolException("Server connection limit outside bounds")
                val negotiated = if (transport.type == TransportType.RUDP_DNS_53) 1 else minOf(maxConnections.toInt(), options.requestedTcpConnections)
                val key = welcome.data("session_key") ?: throw ProtocolException("Missing session key")
                val name = welcome.str("session_name") ?: throw ProtocolException("Missing session name")
                if (key.size != 20 || welcome.str("connection_name") == null) throw ProtocolException("Malformed session welcome")
                val timeout = welcome.int("timeout").toInt()
                if (timeout !in 5000..60000) throw ProtocolException("Invalid session timeout")
                transport.setReadTimeout(timeout)
                val acceleration = transport.remoteAddress?.address?.let { options.udpAcceleration?.negotiate(welcome, it) }
                return SoftEtherSession(transport, name, timeout, key.copyOf(), welcome.int("session_key_32"), options.requestedTcpConnections, negotiated, acceleration)
            } catch (e: Throwable) { runCatching { transport.close() }; throw e }
            finally { hello?.wipe(); login?.wipe(); welcome?.wipe() }
        }
        private fun checkError(p: Pack) { val code = p.int("error"); if (code != 0L) throw SoftEtherServerException(code.toInt()) }
        // CreateNodeInfo stores network-order numbers; OutRpcNodeInfo applies LittleEndian32.
        private fun metadataInt(v: Long) = Integer.reverseBytes(v.toInt()).toLong() and 0xffffffffL
        private fun addAddress(pack: Pack, name4: String, name6: String, socketAddress: java.net.InetSocketAddress?) {
            val bytes = socketAddress?.address?.address
            pack.uint(name4, if (bytes?.size == 4) metadataInt(ByteBuffer.wrap(bytes).int.toLong()) else 0)
                .data(name6, if (bytes?.size == 16) bytes else ByteArray(16))
                .bool("$name4@ipv6_bool", false).data("$name4@ipv6_array", ByteArray(16)).uint("$name4@ipv6_scope_id", 0)
        }
    }
}

/** Connection.c: uint32 batch count, then uint32 size and Ethernet bytes.
 * FFFFFFFF starts a keepalive followed by uint32 size and up to 512 bytes. */
class SoftEtherDataChannel(private val transport: SoftEtherTransport) {
    var onKeepAlive: (ByteArray) -> Unit = {}
    private val input = DataInputStream(transport.input)
    private val output = DataOutputStream(transport.output)
    private var remainingFrames = 0
    private val writeLock = Any()
    fun readFrame(): ByteArray {
        var emptyRecords = 0
        while (true) {
            if (remainingFrames > 0) {
                val size = input.readInt()
                if (size !in 0..1600) throw ProtocolException("Ethernet block exceeds negotiated limit")
                remainingFrames--
                if (size == 0) { if (++emptyRecords > 4096) throw ProtocolException("Excessive empty blocks"); continue }
                if (size < 14) throw ProtocolException("Truncated Ethernet block")
                return ByteArray(size).also { input.readFully(it) }
            }
            val count = input.readInt()
            if (count == -1) {
                val size = input.readInt()
                if (size !in 0..512) throw ProtocolException("Keepalive size exceeds bounds")
                val body = ByteArray(size); input.readFully(body); onKeepAlive(body)
            } else {
                if (count !in 0..4096) throw ProtocolException("Frame batch count exceeds bounds")
                remainingFrames = count
            }
            if (++emptyRecords > 4096) throw ProtocolException("Excessive empty transport records")
        }
    }
    fun sendFrame(frame: ByteArray) = synchronized(writeLock) {
        require(frame.size in 14..1600)
        output.writeInt(1); output.writeInt(frame.size); output.write(frame); output.flush()
    }
    fun keepAlive(body: ByteArray = byteArrayOf()) = synchronized(writeLock) {
        require(body.size <= 512); output.writeInt(-1); output.writeInt(body.size); output.write(body); output.flush()
    }
}
