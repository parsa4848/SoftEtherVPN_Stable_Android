package com.blockto.sevpn.vpn

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.net.VpnService
import android.os.Build
import com.blockto.sevpn.MainActivity
import com.blockto.sevpn.SevpnApplication
import com.blockto.sevpn.dhcp.*
import com.blockto.sevpn.l2.*
import com.blockto.sevpn.network.*
import com.blockto.sevpn.protocol.*
import com.blockto.sevpn.storage.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.selects.*
import java.io.IOException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class AndroidVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var connectionJob: Job? = null
    @Volatile private var attempt: AttemptResources? = null
    private lateinit var networks: UnderlyingNetworkController
    private val repo get() = (application as SevpnApplication).profiles
    override fun onCreate() {
        super.onCreate()
        networks = UnderlyingNetworkController(this)
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(CHANNEL, "VPN connection", NotificationManager.IMPORTANCE_LOW))
        scope.launch { VpnRuntime.status.collect { if (connectionJob?.isActive == true) getSystemService(NotificationManager::class.java).notify(NOTIFICATION, notification(it.message)) } }
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == DISCONNECT) { disconnect(); return START_NOT_STICKY }
        if (intent?.action != CONNECT) { stopSelf(startId); return START_NOT_STICKY }
        if (prepare(this) != null) { VpnRuntime.error("Android VPN permission is required", "PERMISSION"); stopSelf(startId); return START_NOT_STICKY }
        if (connectionJob?.isActive == true) return START_NOT_STICKY
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification("Preparing VPN"), ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIFICATION, notification("Preparing VPN"))
        connectionJob = scope.launch {
            try { withContext(Dispatchers.Default) { connectionLoop() } }
            catch (_: CancellationException) { }
            finally {
                attempt?.close(); attempt = null
                if (VpnRuntime.status.value.phase != VpnPhase.ERROR) VpnRuntime.phase(VpnPhase.IDLE, "Disconnected")
                stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
            }
        }
        return START_NOT_STICKY
    }
    private suspend fun connectionLoop() {
        VpnRuntime.beginConnection()
        val profile = try { repo.load().also { it.validate() } } catch (_: Exception) {
            VpnRuntime.error("Save a valid VPN profile before connecting", "PROFILE"); return
        }
        var failures = 0
        val random = SecureRandom()
        while (currentCoroutineContext().isActive) {
            val resources = AttemptResources(); attempt = resources
            var reachedConnected = false
            val networkChanged = AtomicBoolean(false)
            try {
                if (networks.network.value == null) VpnRuntime.phase(VpnPhase.RECONNECTING, "Waiting for Wi-Fi or mobile network")
                val network = networks.network.filterNotNull().first()
                coroutineScope {
                    // This child closes blocking I/O at the START of cancellation.
                    launch(start = CoroutineStart.UNDISPATCHED) { try { awaitCancellation() } finally { resources.close() } }
                    launch {
                        networks.network.collect { if (it != network) {
                            networkChanged.set(true); resources.close(); throw UnderlyingNetworkChangedException()
                        } }
                    }
                    runSession(profile, network, resources) { reachedConnected = true; failures = 0 }
                }
            } catch (e: CancellationException) { throw e }
            catch (e: Exception) {
                val failure = if (networkChanged.get()) UnderlyingNetworkChangedException() else e
                val errno = generateSequence<Throwable>(failure) { it.cause }.take(8)
                    .filterIsInstance<android.system.ErrnoException>().firstOrNull()?.errno
                val error = ConnectionFailures.classify(failure, VpnRuntime.status.value.phase, errno)
                VpnRuntime.failure(error)
                if (!profile.reconnect || !error.retry) { VpnRuntime.phase(VpnPhase.ERROR, error.message); return }
                failures = if (reachedConnected) 1 else failures + 1
                VpnRuntime.phase(VpnPhase.RECONNECTING, "${error.message}. Reconnecting")
            } finally { resources.close(); if (attempt === resources) attempt = null }
            val backoff = minOf(30_000L, 1000L shl minOf(failures - 1, 5).coerceAtLeast(0))
            delay(backoff + random.nextInt((backoff / 4).toInt().coerceAtLeast(1)))
        }
    }
    @OptIn(ExperimentalCoroutinesApi::class)
    private suspend fun CoroutineScope.runSession(profile: VpnProfile, network: Network, resources: AttemptResources, connected: () -> Unit) {
        VpnRuntime.phase(VpnPhase.CONNECTING_TRANSPORT, "Connecting to server")
        val selected = TransportSelector(this@AndroidVpnService).connect(profile, network, resources, this)
        val transport = selected.stream
        val udpSocket = if (profile.udpAccelerationEnabled && transport.type == TransportType.TCP) try {
            withContext(Dispatchers.IO) { ProtectedDatagrams.create(this@AndroidVpnService, network, resources, transport.localAddress?.address) }
        } catch (e: TransportSetupException) {
            VpnRuntime.diagnostics.failure(ConnectionFailures.classify(e, VpnPhase.CONNECTING_TRANSPORT)); null
        } else null
        val offer = udpSocket?.let { resources.own(UdpAccelerationOffer(java.net.InetSocketAddress(it.localAddress, it.localPort))) }
        val (mac, machine) = repo.ethernetIdentity()
        val password = try { repo.credentials(profile) } catch (_: Exception) { throw ProfileCredentialException() }
        VpnRuntime.phase(VpnPhase.SOFTETHER_HANDSHAKE, "Negotiating SoftEther session")
        val session = try { withContext(Dispatchers.IO) {
            resources.own(SoftEtherSession.connect(transport, profile.host, profile.hub, profile.username, password, machine, SessionOptions(profile.requestedTcpConnections, offer)) {
                VpnRuntime.phase(VpnPhase.AUTHENTICATING, "Authenticating to Virtual Hub")
            })
        } } catch (e: IOException) {
            if (transport.type == TransportType.RUDP_DNS_53 && e !is SoftEtherServerException && e !is RudpException && e !is javax.net.ssl.SSLException)
                throw RudpException(RudpFailure.SOFTETHER_HANDSHAKE)
            throw e
        } finally { password?.fill('\u0000'); machine.fill(0) }
        offer?.close()
        if (session.udpAcceleration == null) udpSocket?.close()
        VpnRuntime.phase(VpnPhase.SESSION_ESTABLISHED, "SoftEther session established")
        var acceleration: UdpAccelerationEngine? = null
        val additional: (suspend () -> AdditionalConnection)? = if (transport.type == TransportType.TCP) ({
            val child = resources.own(AttemptResources())
            try {
                val socket = SoftEtherTlsTransport(this@AndroidVpnService).connect(profile, network, child,
                    transport.remoteAddress?.address, announce = false)
                withContext(Dispatchers.IO) { session.attachAdditional(OwnedTransport(socket, child, resources), profile.host) }
            } catch (e: Throwable) { child.close(); resources.release(child); throw e }
        }) else null
        val pool = resources.own(SoftEtherConnectionPool(session, this, additional,
            keepAliveBody = { acceleration?.keepAliveBody() ?: byteArrayOf() },
            receivedKeepAlive = { acceleration?.receiveKeepAlive(it) }))
        pool.start()
        val accelerationConfig = session.udpAcceleration
        if (udpSocket != null && accelerationConfig != null) {
            acceleration = resources.own(UdpAccelerationEngine(udpSocket, accelerationConfig, this, pool.inbound,
                { pool.sendFrame(it) }, { host -> network.getAllByName(host).firstOrNull { it is java.net.Inet4Address } }))
            acceleration.start()
        }
        val inbound = pool.inbound
        val send: suspend (ByteArray) -> Unit = { if (acceleration?.trySend(it) != true) pool.sendFrame(it) }
        VpnRuntime.phase(VpnPhase.DHCP, "Obtaining IP address from Virtual Hub")
        var lease = DhcpClient(mac, send, inbound, profile.dns()).acquire()
        VpnRuntime.phase(VpnPhase.CONFIGURING_TUN, "Configuring Android VPN")
        setUnderlyingNetworks(arrayOf(network))
        val builder = Builder().setSession(profile.name).setMtu(profile.mtu).setBlocking(false)
            .addAddress(lease.address.toString(), lease.prefix).addRoute("0.0.0.0", 0)
            .setConfigureIntent(PendingIntent.getActivity(this@AndroidVpnService, 0, Intent(this@AndroidVpnService, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE))
        lease.dns.forEach { builder.addDnsServer(it.toString()) }
        // No IPv6 address/route/allowFamily: Android blocks this unsupported family.
        val tun = resources.own(TunDevice(builder.establish() ?: throw TunEstablishException(), profile.mtu))
        val fromTun = Channel<ByteArray>(128); val toTun = Channel<ByteArray>(128); val dhcpReplies = Channel<ByteArray>(16)
        val readerReady = CompletableDeferred<Unit>(); val writerReady = CompletableDeferred<Unit>(); val bridgeReady = CompletableDeferred<Unit>()
        val endpoint = VirtualEthernetEndpoint(mac, Ipv4RoutingEngine(lease.address, lease.prefix, lease.gateway, lease.routes), profile.mtu, send)
        fun publishStatistics() = VpnRuntime.statistics(endpoint.transmittedBytes, endpoint.receivedBytes, SessionStatistics(
            session.requestedTcpConnections, session.negotiatedMaxConnections, pool.activeTcpConnections, transport.type,
            profile.udpAccelerationEnabled, accelerationConfig != null, acceleration?.active == true,
            acceleration?.bytesSent?.get() ?: 0, acceleration?.bytesReceived?.get() ?: 0,
            selected.rudp?.packetsSent?.get() ?: 0, selected.rudp?.packetsReceived?.get() ?: 0, selected.rudp?.retransmissions?.get() ?: 0))
        publishStatistics()
        launch { tun.readPackets(fromTun, readerReady) }
        launch { writerReady.complete(Unit); for (packet in toTun) tun.writePacket(packet) }
        launch {
            endpoint.announce(); bridgeReady.complete(Unit)
            var lastStats = 0L
            while (isActive) {
                select<Unit> {
                    inbound.onReceive { frame ->
                        val dhcp = try { DhcpCodec.parse(frame, mac) } catch (_: PacketException) { null }
                        if (dhcp != null) dhcpReplies.trySend(frame)
                        else endpoint.receive(frame)?.let { toTun.send(it) }
                    }
                    fromTun.onReceive { endpoint.sendIp(it) }
                    onTimeout(250) { }
                }
                endpoint.tick()
                if (monotonic() - lastStats >= 1000) {
                    publishStatistics()
                    lastStats = monotonic()
                }
            }
        }
        launch {
            val renewal = DhcpClient(mac, send, dhcpReplies, profile.dns())
            while (isActive) {
                delay(maxOf(1000, lease.acquiredMs + lease.renewSeconds * 1000 - monotonic()))
                var updated: DhcpLease? = null
                while (updated == null) {
                    val left = lease.expiresMs - monotonic()
                    if (left <= 0) throw DhcpException("DHCP lease expired; reacquiring network configuration")
                    updated = withTimeoutOrNull(left) { renewal.renew(lease) }
                    if (updated == null) delay(minOf(5000, maxOf(1, lease.expiresMs - monotonic())))
                }
                if (!lease.sameConfiguration(updated)) throw DhcpException("DHCP network configuration changed; rebuilding VPN")
                lease = updated
            }
        }
        readerReady.await(); writerReady.await(); bridgeReady.await()
        currentCoroutineContext().ensureActive()
        connected(); VpnRuntime.phase(VpnPhase.CONNECTED, "Connected · ${lease.address}/${lease.prefix}")
        awaitCancellation()
    }
    private fun disconnect() {
        VpnRuntime.phase(VpnPhase.DISCONNECTING, "Disconnecting")
        connectionJob?.cancel(); attempt?.close()
        if (connectionJob == null) { VpnRuntime.phase(VpnPhase.IDLE, "Disconnected"); stopSelf() }
    }
    override fun onRevoke() { connectionJob?.cancel(); attempt?.close(); scope.launch { disconnect() }; super.onRevoke() }
    override fun onDestroy() { connectionJob?.cancel(); attempt?.close(); networks.close(); scope.cancel(); super.onDestroy() }
    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val disconnect = PendingIntent.getService(this, 1, Intent(this, AndroidVpnService::class.java).setAction(DISCONNECT), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CHANNEL).setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("SEVPN")
            .setContentText(message).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Disconnect", disconnect).build()).build()
    }
    companion object {
        const val CONNECT = "com.blockto.sevpn.CONNECT"; const val DISCONNECT = "com.blockto.sevpn.DISCONNECT"
        private const val CHANNEL = "sevpn_connection"; private const val NOTIFICATION = 1
        private fun monotonic() = System.nanoTime() / 1_000_000
    }
}
