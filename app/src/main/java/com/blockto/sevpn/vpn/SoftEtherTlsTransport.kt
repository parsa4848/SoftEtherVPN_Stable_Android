package com.blockto.sevpn.vpn

import android.net.Network
import android.net.VpnService
import com.blockto.sevpn.protocol.SocketTransport
import com.blockto.sevpn.security.TlsPolicy
import com.blockto.sevpn.storage.VpnProfile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

class SoftEtherTlsTransport(private val service: VpnService) {
    suspend fun connect(profile: VpnProfile, network: Network, resources: AttemptResources,
                        address: java.net.InetAddress? = null, announce: Boolean = true): SocketTransport = withContext(Dispatchers.IO) {
        val addresses = if (address == null) network.getAllByName(profile.host) else arrayOf(address)
        currentCoroutineContext().ensureActive()
        var lastError: java.io.IOException? = null
        for (address in addresses) {
            currentCoroutineContext().ensureActive()
            val raw = resources.own(Socket())
            var step = TransportStep.SOCKET_INITIALIZATION
            try {
                TunnelSocketSetup.initialize(raw)
                step = TransportStep.SOCKET_PROTECTION
                if (!service.protect(raw)) throw java.io.IOException("Android could not protect the tunnel socket")
                step = TransportStep.NETWORK_BIND
                network.bindSocket(raw)
                step = TransportStep.TCP_CONNECT
                raw.connect(InetSocketAddress(address, profile.port), 10_000)
                step = TransportStep.TLS_HANDSHAKE
                if (announce) VpnRuntime.phase(VpnPhase.TLS_HANDSHAKE, "Validating server certificate")
                val policy = TlsPolicy(profile.certificatePin.takeIf { it.isNotBlank() })
                val tls = resources.own(policy.socketFactory().createSocket(raw, profile.host, profile.port, true) as SSLSocket)
                policy.configure(tls); tls.soTimeout = 15_000; tls.startHandshake()
                return@withContext resources.own(SocketTransport(tls))
            } catch (e: java.io.IOException) {
                runCatching { raw.close() }
                val failure = TransportSetupException(step, e)
                // Protection/binding and TLS failures need their original cause.
                // Only TCP address failures may fall through to the next address.
                if (step != TransportStep.TCP_CONNECT) throw failure
                lastError = failure
            }
        }
        throw lastError ?: java.io.IOException("No server addresses resolved")
    }
}
