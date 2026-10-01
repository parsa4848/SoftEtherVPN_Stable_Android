package com.blockto.sevpn.protocol

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class ProtocolTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    @Test fun actualUpstreamCFixtures() {
        val props = java.util.Properties().apply { ProtocolTest::class.java.getResourceAsStream("/upstream-vectors.properties")!!.use { load(it) } }
        listOf(0, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128).forEach {
            assertEquals(props.getProperty("sha0_$it"), hex(Sha0.digest(ByteArray(it) { n -> n.toByte() })))
        }
        assertEquals(props.getProperty("password_challenge"), hex(SoftEtherAuthenticator.response("user", "password".toCharArray(), ByteArray(20) { it.toByte() })))
        assertEquals(props.getProperty("pack_string"), hex(SoftEtherPackCodec.encode(Pack().str("method", "login"))))
        assertEquals(props.getProperty("pack_int64"), hex(SoftEtherPackCodec.encode(Pack().put("wide", listOf(PackValue.UInt64(0x0102030405060708))))))
    }
    @Test fun upstreamPackIntegerVector() {
        // WritePack -> WriteElement -> WriteBufStr / WriteValue, big-endian.
        val expected = "000000010000000278000000000000000101020304"
        val b = SoftEtherPackCodec.encode(Pack().uint("x", 0x01020304))
        assertEquals(expected, hex(b))
        assertEquals(0x01020304L, SoftEtherPackCodec.decode(b).int("X"))
    }
    @Test fun allValueTypesAndMultipleValues() {
        val p = Pack().str("method", "login").data("challenge", byteArrayOf(1, 2, -1))
            .put("wide", listOf(PackValue.Unicode("شبکه")))
            .put("i64", listOf(PackValue.UInt64(Long.MIN_VALUE)))
            .put("numbers", listOf(PackValue.UInt(0), PackValue.UInt(0xffffffffL)))
        val q = SoftEtherPackCodec.decode(SoftEtherPackCodec.encode(p))
        assertEquals("login", q.str("method"))
        assertArrayEquals(byteArrayOf(1, 2, -1), q.data("challenge"))
        assertEquals("شبکه", (q.values("wide")!![0] as PackValue.Unicode).value)
        assertEquals(Long.MIN_VALUE, (q.values("i64")!![0] as PackValue.UInt64).bits)
        assertEquals(0xffffffffL, (q.values("numbers")!![1] as PackValue.UInt).value)
    }
    @Test fun sha0KnownVectors() {
        assertEquals("f96cea198ad1dd5617ac084a3d92c6107708c0ef", hex(Sha0.digest(byteArrayOf())))
        assertEquals("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", hex(Sha0.digest("abc".toByteArray())))
        assertEquals("d2516ee1acfa5baf33dfc1c471e438449ef134c8", hex(Sha0.digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".toByteArray())))
    }
    @Test fun passwordPacketUsesChallengeAndAsciiUppercase() {
        val random = ByteArray(20) { it.toByte() }
        val expected = Sha0.digest(Sha0.digest("passwordUSER".toByteArray()) + random)
        val p = SoftEtherAuthenticator.login("HUB", "user", "password".toCharArray(), random)
        assertEquals(1L, p.int("authtype"))
        assertEquals("HUB", p.str("hubname"))
        assertArrayEquals(expected, p.data("secure_password"))
        assertNull(p.str("plain_password"))
        assertArrayEquals(expected, SoftEtherAuthenticator.response("UsEr", "password".toCharArray(), random))
    }
    @Test fun anonymousPacketHasNoSecret() {
        val p = SoftEtherAuthenticator.login("HUB", "guest", null, ByteArray(20))
        assertEquals(0L, p.int("authtype")); assertNull(p.data("secure_password"))
    }
    @Test fun rejectAllTruncationsAndInvalidLengths() {
        val bytes = SoftEtherPackCodec.encode(Pack().data("key", ByteArray(20)))
        for (size in 0 until bytes.size) {
            try { SoftEtherPackCodec.decode(bytes.copyOf(size)); fail("accepted truncated $size") } catch (_: ProtocolException) { }
        }
        val bad = ByteBuffer.allocate(4).putInt(Int.MAX_VALUE).array()
        try { SoftEtherPackCodec.decode(bad); fail() } catch (_: ProtocolException) { }
    }
    @Test fun rejectDuplicateUnknownTypesAndTrailingData() {
        val b = SoftEtherPackCodec.encode(Pack().uint("x", 1))
        val type = b.copyOf().also { ByteBuffer.wrap(it).putInt(9, 999) }
        val duplicate = ByteBuffer.allocate(b.size * 2 - 4).putInt(2).put(b, 4, b.size - 4).put(b, 4, b.size - 4).array()
        listOf(type, duplicate, b + byteArrayOf(0)).forEach {
            try { SoftEtherPackCodec.decode(it); fail() } catch (_: ProtocolException) { }
        }
    }
}
