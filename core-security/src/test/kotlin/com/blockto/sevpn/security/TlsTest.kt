package com.blockto.sevpn.security
import org.junit.Assert.*
import org.junit.Test
import javax.net.ssl.SSLSocket

class TlsTest {
    @Test fun systemTrustEnablesHostnameVerification() {
        val p = TlsPolicy()
        (p.socketFactory().createSocket() as SSLSocket).use {
            p.configure(it)
            assertEquals("HTTPS", it.sslParameters.endpointIdentificationAlgorithm)
            assertTrue(it.enabledProtocols.all { v -> v in setOf("TLSv1.2", "TLSv1.3") })
        }
        assertFalse(p.isPinned)
    }
    @Test fun pinsAreExplicitAndValidated() {
        assertTrue(TlsPolicy("ab".repeat(32)).isPinned)
        for (pin in listOf("", "ab", "zz".repeat(32))) {
            try { TlsPolicy(pin); fail() } catch (_: IllegalArgumentException) {}
        }
    }
}
