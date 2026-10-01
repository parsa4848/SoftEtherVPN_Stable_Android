package com.blockto.sevpn.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class VpnPhase { IDLE, PREPARING, CONNECTING_TRANSPORT, TLS_HANDSHAKE, SOFTETHER_HANDSHAKE,
    AUTHENTICATING, SESSION_ESTABLISHED, DHCP, CONFIGURING_TUN, CONNECTED, RECONNECTING, DISCONNECTING, ERROR }
data class VpnStatus(val phase: VpnPhase = VpnPhase.IDLE, val message: String = "Disconnected",
                     val txBytes: Long = 0, val rxBytes: Long = 0, val connectedAtMs: Long = 0)

object VpnRuntime {
    private val mutable = MutableStateFlow(VpnStatus())
    val status = mutable.asStateFlow()
    val diagnostics = DiagnosticLog()
    fun phase(phase: VpnPhase, message: String = phase.name.lowercase().replace('_', ' ')) {
        mutable.update { it.copy(phase = phase, message = message,
            connectedAtMs = if (phase == VpnPhase.CONNECTED) System.currentTimeMillis() else 0) }
        diagnostics.phase(phase)
    }
    fun statistics(tx: Long, rx: Long) { mutable.update { it.copy(txBytes = tx, rxBytes = rx) } }
    fun error(message: String, category: String, serverCode: Int? = null) { diagnostics.error(category, serverCode); phase(VpnPhase.ERROR, message) }
}

class DiagnosticLog {
    private val lines = ArrayDeque<String>()
    @Synchronized fun phase(phase: VpnPhase) = append("phase=${phase.name}")
    @Synchronized fun error(category: String, code: Int?) { require(category.matches(Regex("[A-Z_]+"))); append("error=$category server_code=${code ?: 0}") }
    private fun append(line: String) { if (lines.size >= 200) lines.removeFirst(); lines.addLast("${java.time.Instant.now()} $line") }
    @Synchronized fun export(): String = "SEVPN sanitized diagnostics v1\n" + lines.joinToString("\n") + "\n" +
        VpnRuntime.status.value.let { "tx_bytes=${it.txBytes} rx_bytes=${it.rxBytes}\n" }
}
