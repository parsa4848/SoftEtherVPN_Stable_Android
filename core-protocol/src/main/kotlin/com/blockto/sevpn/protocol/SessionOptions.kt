package com.blockto.sevpn.protocol

enum class TransportMode { AUTO, TCP, RUDP_DNS_53 }
enum class TransportType { TCP, RUDP_DNS_53 }

class SessionOptions(val requestedTcpConnections: Int = 1, val udpAcceleration: UdpAccelerationOffer? = null) {
    init { require(requestedTcpConnections in 1..32) }
}

data class SessionStatistics(
    val requestedTcpConnections: Int = 1, val negotiatedMaxConnections: Int = 1,
    val activeTcpConnections: Int = 0, val transportType: TransportType = TransportType.TCP,
    val udpAccelerationRequested: Boolean = false, val udpAccelerationNegotiated: Boolean = false,
    val udpAccelerationActive: Boolean = false, val udpAccelerationBytesSent: Long = 0,
    val udpAccelerationBytesReceived: Long = 0, val rudpDnsPacketsSent: Long = 0,
    val rudpDnsPacketsReceived: Long = 0, val rudpDnsRetransmissions: Long = 0
)
