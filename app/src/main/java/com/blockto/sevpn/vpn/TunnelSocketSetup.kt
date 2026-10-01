package com.blockto.sevpn.vpn

import java.net.Socket

internal object TunnelSocketSetup {
    fun initialize(socket: Socket) {
        // Android's Socket constructor leaves the descriptor uncreated.
        // setTcpNoDelay -> getImpl -> createImpl materializes it. In contrast,
        // VpnService.protect(Socket) accesses the descriptor directly.
        // Create it without binding or connecting before asking to protect it.
        socket.tcpNoDelay = true
        socket.soTimeout = 15_000
    }
}
