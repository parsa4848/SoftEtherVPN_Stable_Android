package com.blockto.sevpn.vpn

import com.blockto.sevpn.dhcp.DhcpException
import com.blockto.sevpn.protocol.ProtocolException
import com.blockto.sevpn.protocol.SoftEtherServerException
import com.blockto.sevpn.protocol.RudpException
import com.blockto.sevpn.protocol.RudpFailure
import java.io.EOFException
import java.io.IOException
import java.net.*
import java.security.cert.CertificateException
import javax.net.ssl.SSLException

enum class TransportStep { SOCKET_INITIALIZATION, SOCKET_PROTECTION, NETWORK_BIND, TCP_CONNECT, TLS_HANDSHAKE, UDP_SOCKET }
class TransportSetupException(val step: TransportStep, cause: IOException) : IOException("Transport setup failed: ${step.name}", cause)
class UnderlyingNetworkChangedException : IOException("Physical network changed")
class TunnelWriteStalledException : IOException("Tunnel write stalled")
class TunEstablishException : IOException("Android TUN establishment failed")
class ProfileCredentialException : IOException("Secure credentials unavailable")

/** Only local enums and numeric errno enter exported diagnostics, never Throwable text. */
enum class FailureKind { CREDENTIALS, TLS, SERVER, PROTOCOL, DHCP, TUN, DNS, TCP,
    TIMEOUT, EOF, SOCKET, IO, NETWORK_CHANGED, SOCKET_PROTECTION, NETWORK_BIND,
    WRITE_STALLED, CONFIGURATION, RUDP }
data class ConnectionFailure(val message: String, val category: String, val retry: Boolean,
                             val phase: VpnPhase, val kind: FailureKind,
                             val step: TransportStep? = null, val errno: Int? = null,
                             val serverCode: Int? = null)

object ConnectionFailures {
    fun classify(error: Exception, phase: VpnPhase, errno: Int? = null): ConnectionFailure {
        val chain = generateSequence<Throwable>(error) { it.cause }.take(8).toList()
        val step = chain.filterIsInstance<TransportSetupException>().firstOrNull()?.step
        val stage = when (phase) {
            VpnPhase.CONNECTING_TRANSPORT -> "TCP connection"
            VpnPhase.TLS_HANDSHAKE -> "TLS handshake"
            VpnPhase.SOFTETHER_HANDSHAKE -> "SoftEther hello"
            VpnPhase.AUTHENTICATING -> "SoftEther authentication"
            VpnPhase.SESSION_ESTABLISHED, VpnPhase.DHCP -> "DHCP over the tunnel"
            VpnPhase.CONFIGURING_TUN -> "Android VPN setup"
            VpnPhase.CONNECTED -> "VPN traffic transfer"
            else -> "VPN connection"
        }
        fun result(message: String, category: String, retry: Boolean, kind: FailureKind, code: Int? = null) =
            ConnectionFailure(message, category, retry, phase, kind, step, errno, code)
        if (chain.any { it is UnderlyingNetworkChangedException }) return result("Wi-Fi or mobile network changed", "NETWORK_CHANGED", true, FailureKind.NETWORK_CHANGED)
        if (chain.any { it is ProfileCredentialException }) return result("Save a password again; secure credentials could not be read", "CREDENTIALS", false, FailureKind.CREDENTIALS)
        if (chain.any { it is SSLException || it is CertificateException }) return result("TLS validation failed. Verify the hostname, trusted CA, or explicit certificate pin", "TLS", false, FailureKind.TLS)
        if (step == TransportStep.SOCKET_PROTECTION) return result("Android could not protect the VPN socket. Disconnect other VPN apps and retry", "SOCKET_PROTECTION", false, FailureKind.SOCKET_PROTECTION)
        if (step == TransportStep.NETWORK_BIND) return result("Android could not bind the VPN socket to Wi-Fi or mobile data", "NETWORK_BIND", true, FailureKind.NETWORK_BIND)
        if (step == TransportStep.UDP_SOCKET) return result("Android could not create the UDP socket", "UDP_SOCKET", true, FailureKind.SOCKET)
        chain.filterIsInstance<RudpException>().firstOrNull()?.let {
            return result(it.message ?: "R-UDP failed", "RUDP_${it.failure.name}", it.failure !in setOf(RudpFailure.SIGNATURE, RudpFailure.INVALID_RESPONSE), FailureKind.RUDP)
        }
        chain.filterIsInstance<SoftEtherServerException>().firstOrNull()?.let {
            return result(it.message ?: "SoftEther server rejected the connection", "SERVER", it.code in setOf(3, 10, 11, 13, 14, 15, 16, 20), FailureKind.SERVER, it.code)
        }
        chain.filterIsInstance<ProtocolException>().firstOrNull()?.let { return result(it.message ?: "SoftEther handshake failed", "PROTOCOL", false, FailureKind.PROTOCOL) }
        chain.filterIsInstance<DhcpException>().firstOrNull()?.let { return result(it.message ?: "DHCP failed", "DHCP", true, FailureKind.DHCP) }
        if (chain.any { it is TunEstablishException }) return result("Android VPN could not be established; check VPN consent", "TUN", false, FailureKind.TUN)
        if (chain.any { it is UnknownHostException }) return result("Server DNS resolution failed", "DNS", true, FailureKind.DNS)
        if (chain.any { it is SocketTimeoutException }) return result("$stage timed out", "TIMEOUT", true, FailureKind.TIMEOUT)
        if (chain.any { it is ConnectException }) return result("TCP connection failed. Check the native SoftEther port and server firewall", "TCP", true, FailureKind.TCP)
        if (chain.any { it is TunnelWriteStalledException }) return result("Tunnel writes stalled", "WRITE_STALLED", true, FailureKind.WRITE_STALLED)
        if (chain.any { it is EOFException }) return result("Server closed the connection during $stage", "SERVER_CLOSED", true, FailureKind.EOF)
        if (chain.any { it is SocketException }) return result("Socket failed during $stage", "SOCKET", true, FailureKind.SOCKET)
        if (error is IOException) return result("I/O failed during $stage", "TRANSPORT", true, FailureKind.IO)
        return result("VPN configuration failed; export sanitized diagnostics", "CONFIGURATION", false, FailureKind.CONFIGURATION)
    }
}
