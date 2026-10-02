package com.blockto.sevpn.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import com.blockto.sevpn.protocol.SessionStatistics

enum class VpnPhase { IDLE, PREPARING, CONNECTING_TRANSPORT, TLS_HANDSHAKE, SOFTETHER_HANDSHAKE,
    AUTHENTICATING, SESSION_ESTABLISHED, DHCP, CONFIGURING_TUN, CONNECTED, RECONNECTING, DISCONNECTING, ERROR }
data class VpnStatus(val phase: VpnPhase = VpnPhase.IDLE, val message: String = "Disconnected",
                     val txBytes: Long = 0, val rxBytes: Long = 0, val connectedAtMs: Long = 0,
                     val lastFailure: ConnectionFailure? = null, val session: SessionStatistics = SessionStatistics())

object VpnRuntime {
    private val mutable = MutableStateFlow(VpnStatus())
    val status = mutable.asStateFlow()
    val diagnostics = DiagnosticLog()
    fun beginConnection() { mutable.value = VpnStatus(phase = VpnPhase.PREPARING, message = "Preparing VPN"); diagnostics.phase(VpnPhase.PREPARING) }
    fun failure(failure: ConnectionFailure) { mutable.update { it.copy(lastFailure = failure) }; diagnostics.failure(failure) }
    fun phase(phase: VpnPhase, message: String = phase.name.lowercase().replace('_', ' ')) {
        mutable.update { it.copy(phase = phase, message = message,
            connectedAtMs = if (phase == VpnPhase.CONNECTED) System.currentTimeMillis() else 0) }
        diagnostics.phase(phase)
    }
    fun statistics(tx: Long, rx: Long, session: SessionStatistics = SessionStatistics()) { mutable.update { it.copy(txBytes = tx, rxBytes = rx, session = session) } }
    fun error(message: String, category: String, serverCode: Int? = null) { diagnostics.error(category, serverCode); phase(VpnPhase.ERROR, message) }
}

class DiagnosticLog {
    private val lines = ArrayDeque<String>()
    @Synchronized fun phase(phase: VpnPhase) = append("phase=${phase.name}")
    @Synchronized fun error(category: String, code: Int?) { require(category.matches(Regex("[A-Z_]+"))); append("error=$category server_code=${code ?: 0}") }
    @Synchronized fun failure(failure: ConnectionFailure) {
        require(failure.category.matches(Regex("[A-Z_]+")))
        append("error=${failure.category} stage=${failure.phase.name} cause=${failure.kind.name} operation=${failure.step?.name ?: "NONE"} errno=${failure.errno ?: 0} server_code=${failure.serverCode ?: 0}")
    }
    private fun append(line: String) { if (lines.size >= 200) lines.removeFirst(); lines.addLast("${java.time.Instant.now()} $line") }
    @Synchronized fun export(): String = "SEVPN sanitized diagnostics v2\napp_version=${com.blockto.sevpn.BuildConfig.VERSION_NAME}\n" + lines.joinToString("\n") + "\n" +
        VpnRuntime.status.value.let { "tx_bytes=${it.txBytes} rx_bytes=${it.rxBytes}\n" + it.session.let { s ->
            "transport=${s.transportType} requested_connections=${s.requestedTcpConnections} negotiated_connections=${s.negotiatedMaxConnections} active_tcp_connections=${s.activeTcpConnections}\n" +
            "udp_requested=${s.udpAccelerationRequested} udp_negotiated=${s.udpAccelerationNegotiated} udp_active=${s.udpAccelerationActive} udp_tx=${s.udpAccelerationBytesSent} udp_rx=${s.udpAccelerationBytesReceived}\n" +
            "rudp_dns_tx_packets=${s.rudpDnsPacketsSent} rudp_dns_rx_packets=${s.rudpDnsPacketsReceived} rudp_dns_retransmissions=${s.rudpDnsRetransmissions}\n"
        } }
}
