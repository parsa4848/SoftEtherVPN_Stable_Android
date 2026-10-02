package com.blockto.sevpn

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.input.*
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.blockto.sevpn.vpn.*
import com.blockto.sevpn.protocol.TransportMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private var connectionRequested = false
    private val consent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) { if (connectionRequested) startVpn() }
        else { connectionRequested = false; VpnRuntime.error("Android VPN permission was rejected", "PERMISSION") }
    }
    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { if (connectionRequested) prepareVpn() }
    private val export = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) lifecycleScope.launch {
            runCatching { withContext(Dispatchers.IO) { contentResolver.openOutputStream(uri)?.use { it.write(VpnRuntime.diagnostics.export().toByteArray()) } } }
        }
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        connectionRequested = savedInstanceState?.getBoolean("connection_requested") ?: false
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent {
            val colors = if (isSystemInDarkTheme()) darkColorScheme(primary = Color(0xff73d7c4)) else lightColorScheme(primary = Color(0xff006b60))
            MaterialTheme(colorScheme = colors) { Surface(Modifier.fillMaxSize()) {
                VpnScreen(connect = {
                    connectionRequested = true
                    VpnRuntime.phase(VpnPhase.PREPARING, "Requesting Android VPN consent")
                    if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                        notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
                    else prepareVpn()
                }, disconnect = { connectionRequested = false; startService(Intent(this, AndroidVpnService::class.java).setAction(AndroidVpnService.DISCONNECT)) },
                    exportLog = { export.launch("sevpn-diagnostics.txt") })
            } }
        }
    }
    override fun onSaveInstanceState(outState: Bundle) { outState.putBoolean("connection_requested", connectionRequested); super.onSaveInstanceState(outState) }
    private fun prepareVpn() { val required = VpnService.prepare(this); if (required == null) startVpn() else consent.launch(required) }
    private fun startVpn() {
        try { ContextCompat.startForegroundService(this, Intent(this, AndroidVpnService::class.java).setAction(AndroidVpnService.CONNECT)) }
        catch (_: Exception) { VpnRuntime.error("Android could not start the VPN foreground service", "SERVICE") }
    }
}

@Composable
private fun VpnScreen(connect: () -> Unit, disconnect: () -> Unit, exportLog: () -> Unit, model: ProfileViewModel = viewModel()) {
    val p by model.profile.collectAsStateWithLifecycle()
    val password by model.password.collectAsStateWithLifecycle()
    val formError by model.error.collectAsStateWithLifecycle()
    val saving by model.saving.collectAsStateWithLifecycle()
    val ready by model.ready.collectAsStateWithLifecycle()
    val savedPassword by model.hasSavedPassword.collectAsStateWithLifecycle()
    val status by VpnRuntime.status.collectAsStateWithLifecycle()
    val active = status.phase !in setOf(VpnPhase.IDLE, VpnPhase.ERROR)
    var advanced by remember { mutableStateOf(false) }
    var licenses by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val uiScope = rememberCoroutineScope()
    var elapsed by remember { mutableLongStateOf(0) }
    LaunchedEffect(status.connectedAtMs) {
        while (status.connectedAtMs != 0L) { elapsed = (System.currentTimeMillis() - status.connectedAtMs) / 1000; delay(1000) }
    }
    Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing).verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("SEVPN", style = MaterialTheme.typography.headlineLarge)
        Text("Native SoftEther VPN · IPv4", style = MaterialTheme.typography.bodyMedium)
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(status.message, style = MaterialTheme.typography.titleMedium, color = if (status.phase == VpnPhase.ERROR) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
            if (status.phase != VpnPhase.CONNECTED) status.lastFailure?.let { failure ->
                Text("Last failure: ${failure.message}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            }
            if (status.phase == VpnPhase.CONNECTED) {
                Text("Sent ${formatBytes(status.txBytes)} · Received ${formatBytes(status.rxBytes)} · ${elapsed / 60}m ${elapsed % 60}s")
                val s = status.session
                Text(if (s.transportType == com.blockto.sevpn.protocol.TransportType.TCP)
                    "TCP connections: ${s.activeTcpConnections} · Server allowed: ${s.negotiatedMaxConnections} · Requested: ${s.requestedTcpConnections}"
                    else "Transport: UDP 53 (R-UDP/DNS) · R-UDP connected")
                Text("UDP Acceleration: " + when {
                    s.transportType != com.blockto.sevpn.protocol.TransportType.TCP -> "Not applicable"
                    !s.udpAccelerationRequested -> "Off"
                    s.udpAccelerationActive -> "Active"
                    s.udpAccelerationNegotiated -> "Waiting for UDP · TCP available"
                    else -> "Unavailable · Using TCP"
                })
            } else if (active) LinearProgressIndicator(Modifier.fillMaxWidth())
        } }
        if (!ready) { CircularProgressIndicator(); return@Column }
        val enabled = !active && !saving
        Field("Profile name", p.name, enabled) { model.update { v -> v.copy(name = it) } }
        Field("Server hostname / IP", p.host, enabled) { model.update { v -> v.copy(host = it.trim()) } }
        Field("Port", p.port.takeIf { it != 0 }?.toString() ?: "", enabled, KeyboardType.Number) { text -> model.update { it.copy(port = text.toIntOrNull() ?: 0) } }
        Field("Virtual Hub", p.hub, enabled) { model.update { v -> v.copy(hub = it) } }
        Field("Username", p.username, enabled) { model.update { v -> v.copy(username = it) } }
        if (!p.anonymous) {
            OutlinedTextField(password, { model.password.value = it }, Modifier.fillMaxWidth(), enabled = enabled,
                label = { Text(if (savedPassword) "Password (saved securely)" else "Password") },
                supportingText = { if (savedPassword) Text("Leave blank to keep the saved password for this server and user.") },
                visualTransformation = PasswordVisualTransformation(), singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false))
        }
        formError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { if (active) disconnect() else model.save(connect) }, enabled = !saving,
                modifier = Modifier.weight(1f)) { Text(if (active) "Disconnect" else "Connect") }
            OutlinedButton(onClick = { model.save() }, enabled = enabled) { Text("Save") }
        }
        TextButton(onClick = { advanced = !advanced }) { Text(if (advanced) "Hide advanced settings" else "Advanced settings") }
        if (advanced) {
            Text("Transport", style = MaterialTheme.typography.titleMedium)
            TransportMode.entries.forEach { mode ->
                Row(Modifier.fillMaxWidth()) {
                    RadioButton(p.transportMode == mode, { model.update { it.copy(transportMode = mode) } }, enabled = enabled)
                    Text(when (mode) { TransportMode.AUTO -> "Auto (TCP)"; TransportMode.TCP -> "TCP"; TransportMode.RUDP_DNS_53 -> "UDP 53 (R-UDP/DNS)" }, Modifier.padding(top = 12.dp))
                }
            }
            Text("UDP 53 uses SoftEther R-UDP directly to your server; it requires its VPN-over-DNS listener.", style = MaterialTheme.typography.bodySmall)
            Field("Number of TCP Connections (1–32)", p.requestedTcpConnections.toString(), enabled, KeyboardType.Number) { text -> model.update { it.copy(requestedTcpConnections = text.toIntOrNull() ?: 0) } }
            Toggle("UDP Acceleration", p.udpAccelerationEnabled, enabled) { model.update { v -> v.copy(udpAccelerationEnabled = it) } }
            Text("Acceleration is optional for TCP sessions and falls back to TCP when unavailable. It is separate from UDP 53 transport.", style = MaterialTheme.typography.bodySmall)
            Text("TLS trust", style = MaterialTheme.typography.titleMedium)
            Text(if (p.certificatePin.isBlank()) "System CA trust and hostname verification" else "Explicit SHA-256 certificate identity pin; supports private/self-signed servers")
            Field("SHA-256 leaf certificate fingerprint (optional)", p.certificatePin, enabled) { model.update { v -> v.copy(certificatePin = it.trim()) } }
            Text("Obtain the fingerprint from your server administrator through a trusted channel. Empty uses normal trusted validation.", style = MaterialTheme.typography.bodySmall)
            Field("MTU (576–1500)", p.mtu.toString(), enabled, KeyboardType.Number) { text -> model.update { it.copy(mtu = text.toIntOrNull() ?: 0) } }
            Field("Explicit IPv4 DNS override (comma-separated)", p.dnsOverride, enabled) { model.update { v -> v.copy(dnsOverride = it) } }
            Text("Empty uses DNS from DHCP. No automatic public DNS fallback.", style = MaterialTheme.typography.bodySmall)
            Toggle("Reconnect after transport / network loss", p.reconnect, enabled) { model.update { v -> v.copy(reconnect = it) } }
            Toggle("Anonymous hub authentication", p.anonymous, enabled) { model.update { v -> v.copy(anonymous = it) } }
            Text("Full IPv4 tunnel with TLS certificate validation. IPv6 is blocked while connected. No kill switch during reconnect. Cluster redirects are unsupported.", style = MaterialTheme.typography.bodySmall)
        }
        TextButton(onClick = exportLog) { Text("Export sanitized diagnostics") }
        TextButton(onClick = { uiScope.launch { licenses = withContext(Dispatchers.IO) { context.assets.open("third_party_notices.md").bufferedReader().use { it.readText() } } } }) { Text("Open-source licenses") }
        Text("Requires DHCP and an Internet gateway on the Virtual Hub. SecureNAT is one option.", style = MaterialTheme.typography.bodySmall)
    }
    licenses?.let { content -> AlertDialog(onDismissRequest = { licenses = null }, title = { Text("Open-source licenses") },
        text = { Text(content, Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) },
        confirmButton = { TextButton(onClick = { licenses = null }) { Text("Close") } }) }
}

@Composable private fun Field(label: String, value: String, enabled: Boolean, keyboard: KeyboardType = KeyboardType.Text, change: (String) -> Unit) {
    OutlinedTextField(value, change, Modifier.fillMaxWidth(), enabled = enabled, label = { Text(label) }, singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = keyboard, autoCorrectEnabled = false))
}
@Composable private fun Toggle(label: String, value: Boolean, enabled: Boolean, change: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text(label, Modifier.weight(1f)); Switch(value, change, enabled = enabled) }
}
private fun formatBytes(bytes: Long) = when { bytes >= 1_048_576 -> "${bytes / 1_048_576} MiB"; bytes >= 1024 -> "${bytes / 1024} KiB"; else -> "$bytes B" }
