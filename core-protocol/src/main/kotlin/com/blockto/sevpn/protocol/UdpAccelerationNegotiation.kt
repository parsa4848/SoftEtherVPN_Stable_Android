package com.blockto.sevpn.protocol

import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher

/** Key-bearing objects deliberately have no data-class / diagnostic toString. */
class UdpAccelerationOffer(val endpoint: InetSocketAddress, val maxVersion: Int = if (UdpCrypto.supportsV2()) 2 else 1) : Closeable {
    internal val keyV1 = ByteArray(20).also { SecureRandom().nextBytes(it) }
    internal val keyV2 = ByteArray(128).also { SecureRandom().nextBytes(it) }
    init { require(endpoint.port in 1..65535 && maxVersion in 1..2) }
    fun advertise(pack: Pack) {
        pack.bool("use_udp_acceleration", true).uint("udp_acceleration_version", 1)
            .uint("udp_acceleration_max_version", maxVersion.toLong())
            .uint("udp_acceleration_client_port", endpoint.port.toLong())
            .data("udp_acceleration_client_key", keyV1.copyOf()).data("udp_acceleration_client_key_v2", keyV2.copyOf())
            .bool("support_hmac_on_udp_acceleration", true).bool("support_udp_accel_fast_disconnect_detect", true)
        PackIp.write(pack, "udp_acceleration_client_ip", endpoint.address.takeUnless { it.isLoopbackAddress })
    }
    fun negotiate(welcome: Pack, remote: InetAddress): UdpAccelerationConfig? {
        if (!welcome.bool("use_udp_acceleration")) return null
        val version = welcome.int("udp_acceleration_version", 1).toInt().let { if (it == 0) 1 else it }
        val serverKey = welcome.data(if (version == 2) "udp_acceleration_server_key_v2" else "udp_acceleration_server_key") ?: return null
        val ip = PackIp.read(welcome, "udp_acceleration_server_ip") ?: return null
        val destination = if (ip.isAnyLocalAddress) remote else ip
        val port = welcome.int("udp_acceleration_server_port")
        val mine = welcome.int("udp_acceleration_client_cookie"); val theirs = welcome.int("udp_acceleration_server_cookie")
        if (version !in 1..maxVersion || serverKey.size != if (version == 2) 128 else 20) return null
        if (port !in 1..65535 || mine == 0L || theirs == 0L || destination.isMulticastAddress || destination.address.size != endpoint.address.address.size) return null
        // This app never accepts unauthenticated plaintext acceleration.
        if (!welcome.bool("udp_acceleration_use_encryption")) return null
        return UdpAccelerationConfig(version, InetSocketAddress(destination, port.toInt()), remote,
            if (version == 2) keyV2.copyOf() else keyV1.copyOf(), serverKey.copyOf(), mine, theirs,
            welcome.bool("udp_accel_fast_disconnect_detect"))
    }
    override fun close() { keyV1.fill(0); keyV2.fill(0) }
}

class UdpAccelerationConfig internal constructor(val version: Int, val endpoint: InetSocketAddress,
    val alternateAddress: InetAddress, internal val sendKey: ByteArray, internal val receiveKey: ByteArray,
    internal val myCookie: Long, internal val yourCookie: Long, val fastDetect: Boolean) : Closeable {
    override fun close() { sendKey.fill(0); receiveKey.fill(0) }
}

internal object PackIp {
    fun write(pack: Pack, name: String, address: InetAddress?) {
        val bytes = address?.address
        pack.uint(name, if (bytes?.size == 4) Integer.reverseBytes(ByteBuffer.wrap(bytes).int).toLong() and 0xffffffffL else 0)
            .bool("$name@ipv6_bool", bytes?.size == 16)
            .data("$name@ipv6_array", if (bytes?.size == 16) bytes.copyOf() else ByteArray(16))
            .uint("$name@ipv6_scope_id", 0)
    }
    fun read(pack: Pack, name: String): InetAddress? {
        if (pack.bool("$name@ipv6_bool")) return pack.data("$name@ipv6_array")?.takeIf { it.size == 16 }?.let { InetAddress.getByAddress(it) }
        if (pack.values(name)?.singleOrNull() !is PackValue.UInt) return null
        return InetAddress.getByAddress(ByteBuffer.allocate(4).putInt(Integer.reverseBytes(pack.int(name).toInt())).array())
    }
}

internal object UdpCrypto {
    fun cipher(): Cipher = try { Cipher.getInstance("ChaCha20-Poly1305") }
        catch (_: java.security.GeneralSecurityException) { Cipher.getInstance("ChaCha20/Poly1305/NoPadding") }
    fun supportsV2() = try { cipher(); true } catch (_: java.security.GeneralSecurityException) { false }
}
