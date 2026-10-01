package com.blockto.sevpn.vpn

import android.content.Context
import android.net.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.Closeable

class UnderlyingNetworkController(context: Context) : Closeable {
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    private val mutable = MutableStateFlow<Network?>(null)
    val network = mutable.asStateFlow()
    private val candidates = linkedSetOf<Network>()
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { synchronized(candidates) { candidates += network; update() } }
        override fun onLost(network: Network) { synchronized(candidates) { candidates -= network; update() } }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { synchronized(candidates) { update() } }
    }
    init {
        synchronized(candidates) {
            candidates.addAll(manager.allNetworks.filter { isPhysical(it) }); update()
        }
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
    }
    private fun isPhysical(network: Network) = manager.getNetworkCapabilities(network)?.let {
        it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    } == true
    private fun update() {
        val active = manager.activeNetwork
        mutable.value = if (active != null && active in candidates && isPhysical(active)) active
        else candidates.filter { isPhysical(it) }.sortedByDescending {
            manager.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        }.firstOrNull()
    }
    override fun close() { manager.unregisterNetworkCallback(callback); mutable.value = null }
}
