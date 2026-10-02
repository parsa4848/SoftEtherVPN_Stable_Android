package com.blockto.sevpn.storage

import android.content.Context
import androidx.datastore.preferences.core.*
import androidx.datastore.preferences.preferencesDataStore
import com.blockto.sevpn.l2.Mac
import com.blockto.sevpn.protocol.TransportMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.security.SecureRandom

private val Context.profileData by preferencesDataStore("vpn_profile")

class VpnProfileRepository(private val context: Context) {
    private val secrets = CredentialStore()
    companion object {
        private val name = stringPreferencesKey("name"); private val host = stringPreferencesKey("host")
        private val port = intPreferencesKey("port"); private val hub = stringPreferencesKey("hub")
        private val username = stringPreferencesKey("username"); private val pin = stringPreferencesKey("certificate_pin")
        private val mtu = intPreferencesKey("mtu"); private val reconnect = booleanPreferencesKey("reconnect")
        private val anonymous = booleanPreferencesKey("anonymous"); private val dns = stringPreferencesKey("dns")
        private val password = stringPreferencesKey("password_aes_gcm"); private val mac = longPreferencesKey("mac")
        private val machine = stringPreferencesKey("machine_id")
        private val count = intPreferencesKey("tcp_connection_count")
        private val acceleration = booleanPreferencesKey("udp_acceleration_enabled")
        private val transport = stringPreferencesKey("transport_mode")
        internal fun profile(p: Preferences) = VpnProfile(p[name] ?: "SoftEther VPN", p[host] ?: "", p[port] ?: 443, p[hub] ?: "", p[username] ?: "", p[pin] ?: "", p[mtu] ?: 1400, p[reconnect] ?: true, p[anonymous] ?: false, p[dns] ?: "",
            p[count] ?: 1, p[acceleration] ?: false, TransportMode.entries.firstOrNull { it.name == p[transport] } ?: TransportMode.TCP)
    }
    suspend fun load(): VpnProfile = profile(context.profileData.data.first())
    suspend fun hasPassword() = !context.profileData.data.first()[password].isNullOrEmpty()
    suspend fun save(v: VpnProfile, newPassword: CharArray?) = withContext(Dispatchers.IO) {
        v.validate()
        if (newPassword != null) require(newPassword.size <= 4096) { "Password is too long" }
        val encrypted = if (newPassword != null && !v.anonymous) secrets.encrypt(newPassword, v.identity) else null
        context.profileData.edit { p ->
            val sameIdentity = profile(p).identity == v.identity
            p[name] = v.name; p[host] = v.host; p[port] = v.port; p[hub] = v.hub; p[username] = v.username
            p[pin] = v.certificatePin; p[mtu] = v.mtu; p[reconnect] = v.reconnect; p[anonymous] = v.anonymous; p[dns] = v.dnsOverride
            p[count] = v.requestedTcpConnections; p[acceleration] = v.udpAccelerationEnabled; p[transport] = v.transportMode.name
            if (encrypted != null) p[password] = encrypted else if (!sameIdentity || v.anonymous) p.remove(password)
            if (p[mac] == null) p[mac] = Mac.generate().bits
            if (p[machine] == null) p[machine] = android.util.Base64.encodeToString(ByteArray(20).also { SecureRandom().nextBytes(it) }, android.util.Base64.NO_WRAP)
        }
    }
    suspend fun credentials(v: VpnProfile): CharArray? = withContext(Dispatchers.IO) {
        if (v.anonymous) return@withContext null
        val p = context.profileData.data.first()
        val blob = p[password] ?: error("Enter and save a password for this profile")
        secrets.decrypt(blob, v.identity)
    }
    suspend fun ethernetIdentity(): Pair<Mac, ByteArray> {
        val p = context.profileData.data.first()
        return Mac(p[mac] ?: error("Save a profile first")) to android.util.Base64.decode(p[machine] ?: error("Missing client identity"), android.util.Base64.NO_WRAP)
    }
}
