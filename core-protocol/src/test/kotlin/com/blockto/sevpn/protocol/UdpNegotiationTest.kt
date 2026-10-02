package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test
import java.net.InetSocketAddress

class UdpNegotiationTest {
    private val endpoint = InetSocketAddress("192.0.2.1", 40001)
    private fun welcome() = Pack().bool("use_udp_acceleration", true).uint("udp_acceleration_version", 2)
        .uint("udp_acceleration_server_port", 40000).data("udp_acceleration_server_key_v2", ByteArray(128))
        .uint("udp_acceleration_client_cookie", 1).uint("udp_acceleration_server_cookie", 2)
        .bool("udp_acceleration_use_encryption", true).also { PackIp.write(it, "udp_acceleration_server_ip", endpoint.address) }
    @Test fun exactOfferAndServerRejection() {
        UdpAccelerationOffer(endpoint, 2).use { offer ->
            val p = Pack(); offer.advertise(p)
            assertEquals(2L, p.int("udp_acceleration_max_version")); assertEquals(40001L, p.int("udp_acceleration_client_port"))
            assertEquals(20, p.data("udp_acceleration_client_key")!!.size); assertEquals(128, p.data("udp_acceleration_client_key_v2")!!.size)
            assertEquals(endpoint.address, PackIp.read(p, "udp_acceleration_client_ip"))
            assertNull(offer.negotiate(Pack(), endpoint.address))
            offer.negotiate(welcome(), endpoint.address)!!.use { assertEquals(2, it.version) }
        }
    }
    @Test fun invalidNegotiationFallsBackInsteadOfFailingSession() {
        UdpAccelerationOffer(endpoint, 2).use { offer ->
            listOf(welcome().uint("udp_acceleration_server_port", 65536), welcome().uint("udp_acceleration_server_cookie", 0),
                welcome().data("udp_acceleration_server_key_v2", ByteArray(32)), welcome().uint("udp_acceleration_version", 3),
                welcome().bool("udp_acceleration_use_encryption", false)).forEach { assertNull(offer.negotiate(it, endpoint.address)) }
        }
    }
}
