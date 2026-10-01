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
    private val selection = PhysicalNetworkSelection<Network>()
    private var closed = false
    private val callback = object : ConnectivityManager.NetworkCallback() {
        // On API 26+, onAvailable is followed by ordered capability data.
        // Publishing before that data arrives would create a spurious loss.
        override fun onLost(network: Network) { synchronized(selection) {
            if (!closed) mutable.value = selection.lost(network)
        } }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { synchronized(selection) {
            if (!closed) mutable.value = selection.capabilities(network, PhysicalNetworkSelection.Capabilities(
                internet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                physical = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
                validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                preference = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 20
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 10
                    else -> 0
                }
            ))
        } }
    }
    init {
        manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
    }
    override fun close() {
        synchronized(selection) { closed = true; mutable.value = null }
        manager.unregisterNetworkCallback(callback)
    }
}
