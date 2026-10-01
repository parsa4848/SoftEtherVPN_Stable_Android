package com.blockto.sevpn

import com.blockto.sevpn.vpn.AttemptResources
import com.blockto.sevpn.vpn.DiagnosticLog
import com.blockto.sevpn.vpn.VpnPhase
import com.blockto.sevpn.storage.VpnProfile
import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.io.IOException

class ResourceLifecycleTest {
    @Test fun cleanupIsIdempotentAndClosesResourcesPublishedAfterCancellation() {
        val resources = AttemptResources(); val closed = mutableListOf<String>()
        resources.own(Closeable { closed += "socket" }); resources.own(Closeable { closed += "tun" })
        resources.close(); resources.close()
        assertEquals(listOf("socket", "tun"), closed)
        try { resources.own(Closeable { closed += "late_socket" }); fail() } catch (_: IOException) {}
        assertEquals(listOf("socket", "tun", "late_socket"), closed)
    }
    @Test fun oneFailingCloseDoesNotPreventOtherResourcesClosing() {
        var closed = false
        val resources = AttemptResources()
        resources.own(Closeable { throw IOException("synthetic cleanup failure") })
        resources.own(Closeable { closed = true }); resources.close(); assertTrue(closed)
    }
    @Test fun diagnosticsAreBoundedAndContainOnlySanitizedCategories() {
        val log = DiagnosticLog()
        repeat(300) { log.phase(VpnPhase.CONNECTING_TRANSPORT) }
        log.error("SERVER", 9)
        val text = log.export()
        assertTrue(text.lines().size <= 205)
        assertTrue(text.contains("server_code=9"))
        try { log.error("password=unsafe", null); fail() } catch (_: IllegalArgumentException) {}
    }
    @Test fun profileRejectsUrlsBadPinsAndUnusableDns() {
        val p = VpnProfile(host = "vpn.example.org", hub = "TEST", username = "user")
        p.validate()
        listOf(p.copy(host = "https://vpn.example.org"), p.copy(port = 0), p.copy(certificatePin = "bad"), p.copy(dnsOverride = "127.0.0.1"), p.copy(mtu = 1600)).forEach {
            try { it.validate(); fail() } catch (_: IllegalArgumentException) {}
        }
    }
}
