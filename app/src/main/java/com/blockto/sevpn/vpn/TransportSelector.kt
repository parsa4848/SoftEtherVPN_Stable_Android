package com.blockto.sevpn.vpn

import android.net.Network
import android.net.VpnService
import com.blockto.sevpn.protocol.*
import com.blockto.sevpn.security.*
import com.blockto.sevpn.storage.VpnProfile
import kotlinx.coroutines.*
import java.net.Inet4Address
import java.net.InetSocketAddress

internal class SelectedTransport(val stream: SoftEtherTransport, val rudp: RudpDnsTransport? = null)

internal class TransportSelector(private val service: VpnService) {
    suspend fun connect(profile: VpnProfile, network: Network, resources: AttemptResources, scope: CoroutineScope): SelectedTransport {
        // Auto preserves the established reliable path. Explicit TCP never races UDP.
        if (profile.transportMode != TransportMode.RUDP_DNS_53)
            return SelectedTransport(SoftEtherTlsTransport(service).connect(profile, network, resources))
        val address = withContext(Dispatchers.IO) { network.getAllByName(profile.host).firstOrNull { it is Inet4Address }
            ?: throw java.net.UnknownHostException("UDP/53 requires a server IPv4 address") }
        currentCoroutineContext().ensureActive()
        val socket = withContext(Dispatchers.IO) { ProtectedDatagrams.create(service, network, resources) }
        val rudp = resources.own(RudpDnsTransport(socket, InetSocketAddress(address, 53), scope))
        rudp.establish()
        VpnRuntime.phase(VpnPhase.TLS_HANDSHAKE, "Validating server certificate over UDP 53")
        val tls = resources.own(StreamTlsTransport(rudp, TlsPolicy(profile.certificatePin.takeIf { it.isNotBlank() }).engine(profile.host, profile.port)))
        withContext(Dispatchers.IO) { tls.handshake() }
        return SelectedTransport(tls, rudp)
    }
}
