package com.blockto.sevpn

import androidx.datastore.preferences.core.*
import com.blockto.sevpn.storage.VpnProfileRepository
import com.blockto.sevpn.protocol.TransportMode
import org.junit.Assert.*
import org.junit.Test

class ProfilePreferencesTest {
    @Test fun oldSavedProfileRetainsIdentityAndReceivesCompatibleDefaults() {
        val old = preferencesOf(stringPreferencesKey("host") to "vpn.example.org",
            intPreferencesKey("port") to 5555, stringPreferencesKey("hub") to "TEST",
            stringPreferencesKey("username") to "alice")
        val profile = VpnProfileRepository.profile(old)
        assertEquals("vpn.example.org", profile.host); assertEquals(5555, profile.port)
        assertEquals("TEST", profile.hub); assertEquals("alice", profile.username)
        assertEquals(1, profile.requestedTcpConnections); assertFalse(profile.udpAccelerationEnabled)
        assertEquals(TransportMode.TCP, profile.transportMode)
    }
    @Test fun savedTransportOptionsAndUnknownEnumAreDecodedSafely() {
        val values = mutablePreferencesOf(intPreferencesKey("tcp_connection_count") to 32,
            booleanPreferencesKey("udp_acceleration_enabled") to true,
            stringPreferencesKey("transport_mode") to "RUDP_DNS_53")
        val p = VpnProfileRepository.profile(values)
        assertEquals(32, p.requestedTcpConnections); assertTrue(p.udpAccelerationEnabled)
        assertEquals(TransportMode.RUDP_DNS_53, p.transportMode)
        values[stringPreferencesKey("transport_mode")] = "UNKNOWN_FUTURE_MODE"
        assertEquals(TransportMode.TCP, VpnProfileRepository.profile(values).transportMode)
    }
}
