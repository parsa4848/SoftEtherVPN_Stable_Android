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
    suspend fun connect(profile: VpnProfile, network: Network, resources: AttemptResources): SocketTransport = withContext(Dispatchers.IO) {
        val addresses = network.getAllByName(profile.host)
        currentCoroutineContext().ensureActive()
        var lastError: java.io.IOException? = null
        for (address in addresses) {
            currentCoroutineContext().ensureActive()
            val raw = resources.own(Socket())
            try {
                if (!service.protect(raw)) throw java.io.IOException("Android could not protect the tunnel socket")
                network.bindSocket(raw)
                raw.tcpNoDelay = true; raw.soTimeout = 15_000
                raw.connect(InetSocketAddress(address, profile.port), 10_000)
                VpnRuntime.phase(VpnPhase.TLS_HANDSHAKE, "Validating server certificate")
                val policy = TlsPolicy(profile.certificatePin.takeIf { it.isNotBlank() })
                val tls = resources.own(policy.socketFactory().createSocket(raw, profile.host, profile.port, true) as SSLSocket)
                policy.configure(tls); tls.soTimeout = 15_000; tls.startHandshake()
                return@withContext resources.own(SocketTransport(tls))
            } catch (e: javax.net.ssl.SSLException) { raw.close(); throw e }
            catch (e: java.io.IOException) { raw.close(); lastError = e }
        }
        throw lastError ?: java.io.IOException("No server addresses resolved")
    }
}
