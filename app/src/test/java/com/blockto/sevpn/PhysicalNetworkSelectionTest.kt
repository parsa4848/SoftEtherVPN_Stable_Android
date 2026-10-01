package com.blockto.sevpn

import com.blockto.sevpn.vpn.PhysicalNetworkSelection
import org.junit.Assert.*
import org.junit.Test

class PhysicalNetworkSelectionTest {
    private fun caps(wifi: Boolean = true, validated: Boolean = true, physical: Boolean = true,
                     internet: Boolean = true) = PhysicalNetworkSelection.Capabilities(internet, physical, validated, if (wifi) 10 else 0)
    @Test fun vpnCreationAndRepeatedCapabilitiesKeepThePhysicalTransport() {
        val s = PhysicalNetworkSelection<String>()
        assertEquals("wifi", s.capabilities("wifi", caps()))
        assertEquals("wifi", s.capabilities("vpn", caps(physical = false)))
        repeat(10) { assertEquals("wifi", s.capabilities("wifi", caps())) }
        assertEquals("wifi", s.lost("vpn"))
    }
    @Test fun validMobileNetworkWinsOverUnvalidatedWifi() {
        val s = PhysicalNetworkSelection<String>()
        s.capabilities("mobile", caps(wifi = false))
        assertEquals("mobile", s.capabilities("wifi", caps(validated = false)))
        assertEquals("wifi", s.capabilities("wifi", caps()))
    }
    @Test fun realNetworkLossFallsBackThenReportsUnavailable() {
        val s = PhysicalNetworkSelection<String>()
        s.capabilities("wifi", caps()); s.capabilities("mobile", caps(wifi = false))
        assertEquals("mobile", s.lost("wifi"))
        assertNull(s.lost("mobile"))
    }
    @Test fun equalPriorityEventsDoNotOscillateAndCapabilityLossIsReal() {
        val s = PhysicalNetworkSelection<String>()
        s.capabilities("first", caps())
        assertEquals("first", s.capabilities("second", caps()))
        repeat(10) { assertEquals("first", s.capabilities("second", caps())) }
        assertEquals("second", s.capabilities("first", caps(internet = false)))
        assertNull(s.capabilities("second", caps(physical = false)))
    }
}
