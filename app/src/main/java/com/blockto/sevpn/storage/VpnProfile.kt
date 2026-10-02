package com.blockto.sevpn.storage

import com.blockto.sevpn.network.Ipv4
import com.blockto.sevpn.security.TlsPolicy
import com.blockto.sevpn.protocol.TransportMode

data class VpnProfile(
    val name: String = "SoftEther VPN", val host: String = "", val port: Int = 443,
    val hub: String = "", val username: String = "", val certificatePin: String = "",
    val mtu: Int = 1400, val reconnect: Boolean = true, val anonymous: Boolean = false,
    val dnsOverride: String = "", val requestedTcpConnections: Int = 1,
    val udpAccelerationEnabled: Boolean = false, val transportMode: TransportMode = TransportMode.TCP
) {
    val identity get() = "$host:$port/$hub/$username"
    fun dns() = dnsOverride.split(',').map { it.trim() }.filter { it.isNotEmpty() }.map { Ipv4.parse(it) }
    fun validate() {
        require(name.isNotBlank() && name.length <= 80) { "Enter a profile name (up to 80 characters)" }
        require(host.isNotEmpty() && host.length <= 253 && host.matches(Regex("[A-Za-z0-9._:-]+"))) { "Enter a hostname or IP address without a URL prefix" }
        require(port in 1..65535) { "Port must be between 1 and 65535" }
        require(hub.toByteArray().size in 1..255 && '\u0000' !in hub) { "Enter a Virtual Hub" }
        require(username.length in 1..255 && username.all { it.code in 32..126 }) { "Enter an ASCII SoftEther username" }
        require(mtu in 576..1500) { "MTU must be between 576 and 1500" }
        require(requestedTcpConnections in 1..32) { "Number of TCP connections must be between 1 and 32" }
        TlsPolicy(certificatePin.takeIf { it.isNotBlank() })
        val addresses = dns(); require(addresses.size <= 8 && addresses.all { it.isUnicast() }) { "DNS override requires usable IPv4 addresses separated by commas" }
    }
}
