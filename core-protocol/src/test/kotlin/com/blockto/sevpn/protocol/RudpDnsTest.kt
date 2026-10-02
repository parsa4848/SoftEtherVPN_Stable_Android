package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test

class RudpDnsTest {
    @Test fun exactCQueryResponseOffsetsIdAndLength() {
        val payload = ByteArray(60) { (it + 7).toByte() }
        val query = RudpDnsCodec.query(payload, byteArrayOf(0x34, 0x12), byteArrayOf(0, 1, 2, 3))
        assertArrayEquals(transportVector("dns_query"), query)
        assertEquals(97, query.size)
        val response = transportVector("dns_response")
        assertArrayEquals(payload, RudpDnsCodec.responsePayload(response))
        // Stock responds with the most recently seen ID, not necessarily a
        // one-to-one query ID; authenticity comes from the R-UDP signature.
        response[0] = 1; response[1] = 2
        assertArrayEquals(payload, RudpDnsCodec.responsePayload(response))
    }
    @Test fun malformedWrapperAndOversizedPacketRejection() {
        val valid = transportVector("dns_response")
        for (i in listOf(2, 3, 12, 21, 22, 25, 26, 36, 37, 38, 39, 40, 41)) {
            try { RudpDnsCodec.responsePayload(valid.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }); fail() } catch (_: RudpException) {}
        }
        for (n in 0..42) try { RudpDnsCodec.responsePayload(valid.copyOf(n)); fail() } catch (_: RudpException) {}
        try { RudpDnsCodec.query(ByteArray(1356), byteArrayOf(1, 2), ByteArray(4)); fail() } catch (_: IllegalArgumentException) {}
        assertEquals(1392, RudpDnsCodec.query(ByteArray(1355), byteArrayOf(1, 2), ByteArray(4)).size)
        val random = java.util.Random(3)
        repeat(2000) { try { RudpDnsCodec.responsePayload(ByteArray(random.nextInt(1500)).also { random.nextBytes(it) }) } catch (_: RudpException) {} }
    }
}
