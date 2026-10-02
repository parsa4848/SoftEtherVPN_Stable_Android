package com.blockto.sevpn.vpn

import android.net.Network
import android.net.VpnService
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.io.IOException

internal object ProtectedDatagrams {
    fun create(service: VpnService, network: Network, resources: AttemptResources, local: InetAddress? = null): DatagramSocket =
        create(resources, { service.protect(it) }, { network.bindSocket(it) }, local)

    internal fun create(resources: AttemptResources, protect: (DatagramSocket) -> Boolean,
        bindNetwork: (DatagramSocket) -> Unit, local: InetAddress? = null): DatagramSocket {
        var step = TransportStep.UDP_SOCKET
        var socket: DatagramSocket? = null
        var complete = false
        try {
            // DatagramSocket(null) creates the OS descriptor without binding.
            val created = resources.own(DatagramSocket(null)); socket = created
            step = TransportStep.SOCKET_PROTECTION
            if (!protect(created)) throw IOException("Android could not protect the UDP socket")
            step = TransportStep.NETWORK_BIND
            bindNetwork(created)
            created.bind(InetSocketAddress(local, 0)); created.soTimeout = 100
            complete = true
            return created
        } catch (e: IOException) { throw TransportSetupException(step, e) }
        finally { if (!complete) socket?.let { it.close(); resources.release(it) } }
    }
}
