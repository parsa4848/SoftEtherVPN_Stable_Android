package com.blockto.sevpn.vpn

/** Callback-owned snapshots: never query ConnectivityManager from its callbacks. */
internal class PhysicalNetworkSelection<N> {
    data class Capabilities(val internet: Boolean, val physical: Boolean,
                            val validated: Boolean, val preference: Int) {
        val usable get() = internet && physical
        val rank get() = (if (validated) 100 else 0) + preference
    }
    private val candidates = linkedMapOf<N, Capabilities>()
    var selected: N? = null
        private set

    fun capabilities(network: N, capabilities: Capabilities): N? {
        if (capabilities.usable) candidates[network] = capabilities else candidates.remove(network)
        return select()
    }
    fun lost(network: N): N? { candidates.remove(network); return select() }
    private fun select(): N? {
        val best = candidates.maxByOrNull { it.value.rank }
        // Keep the existing physical network on equal priority. VPN creation,
        // metering and callback ordering must not cause a transport restart.
        if (best == null) selected = null
        else if (candidates[selected]?.rank != best.value.rank) selected = best.key
        return selected
    }
}
