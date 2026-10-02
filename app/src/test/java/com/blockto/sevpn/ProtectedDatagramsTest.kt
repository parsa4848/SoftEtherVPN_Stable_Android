package com.blockto.sevpn

import com.blockto.sevpn.vpn.*
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException
import java.net.DatagramSocket

class ProtectedDatagramsTest {
    @Test fun protectionPrecedesNetworkBindingAndDatagrams() {
        val resources = AttemptResources(); val order = mutableListOf<String>()
        val socket = ProtectedDatagrams.create(resources, {
            assertFalse(it.isBound); assertFalse(it.isConnected); order += "protect"; true
        }, { assertFalse(it.isBound); order += "network" })
        assertEquals(listOf("protect", "network"), order)
        assertTrue(socket.isBound)
        resources.close(); assertTrue(socket.isClosed)
    }
    @Test fun rejectedProtectionClosesSocketWithoutBindingNetwork() {
        val resources = AttemptResources(); var rejected: DatagramSocket? = null
        try {
            ProtectedDatagrams.create(resources, { rejected = it; false }, { fail("Must not bind an unprotected socket") })
            fail()
        } catch (e: TransportSetupException) { assertEquals(TransportStep.SOCKET_PROTECTION, e.step) }
        assertTrue(rejected!!.isClosed); assertFalse(rejected!!.isBound)
        resources.close()
    }
    @Test fun failedNetworkBindingClosesSocketImmediately() {
        val resources = AttemptResources(); var rejected: DatagramSocket? = null
        try {
            ProtectedDatagrams.create(resources, { rejected = it; true }, { throw IOException("synthetic bind failure") })
            fail()
        } catch (e: TransportSetupException) { assertEquals(TransportStep.NETWORK_BIND, e.step) }
        assertTrue(rejected!!.isClosed); resources.close()
    }
}
