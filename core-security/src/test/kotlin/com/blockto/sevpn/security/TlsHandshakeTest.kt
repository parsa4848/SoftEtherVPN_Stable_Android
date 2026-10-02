package com.blockto.sevpn.security

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.*
import com.blockto.sevpn.protocol.SocketTransport

/** Actual loopback TLS handshakes; ephemeral test key material, never user keys. */
class TlsHandshakeTest {
    private fun fixture(): Pair<SSLContext, KeyStore> {
        val path = File("build/tls-test-${System.nanoTime()}.p12"); path.parentFile.mkdirs()
        if (!path.exists()) {
            val keytool = File(System.getProperty("java.home"), "bin/keytool${if (System.getProperty("os.name").startsWith("Windows")) ".exe" else ""}")
            val p = ProcessBuilder(keytool.path, "-genkeypair", "-alias", "fixture", "-keystore", path.path,
                "-storetype", "PKCS12", "-storepass", "fixture-test-only", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "7", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
            check(p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0)
        }
        val store = KeyStore.getInstance("PKCS12").apply { path.inputStream().use { load(it, "fixture-test-only".toCharArray()) } }
        path.delete()
        val km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "fixture-test-only".toCharArray()) }
        return SSLContext.getInstance("TLS").apply { init(km.keyManagers, null, null) } to store
    }
    @Test fun pinAcceptsExactCertificateAndRejectsMismatchAndUnknownCa() {
        val (serverContext, store) = fixture()
        val cert = store.getCertificate("fixture")
        val pin = MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }
        handshake(serverContext, TlsPolicy(pin), true)
        handshake(serverContext, TlsPolicy("00".repeat(32)), false)
        handshake(serverContext, TlsPolicy(), false)
    }
    @Test fun trustedCertificateStillRequiresCorrectHostname() {
        val (serverContext, store) = fixture()
        val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val clientContext = SSLContext.getInstance("TLS").apply { init(null, tm.trustManagers, null) }
        handshake(serverContext, TlsPolicy(), true, clientContext.socketFactory, "localhost")
        handshake(serverContext, TlsPolicy(), false, clientContext.socketFactory, "wrong.example")
    }
    @Test fun engineOverStreamsPreservesPinnedAndTrustedTlsAndCarriesBytes() {
        val (serverContext, store) = fixture()
        val pin = MessageDigest.getInstance("SHA-256").digest(store.getCertificate("fixture").encoded).joinToString("") { "%02x".format(it) }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val trusted = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
        for ((policy, identity, succeeds) in listOf(Triple(TlsPolicy(pin), "localhost", true), Triple(TlsPolicy("00".repeat(32)), "localhost", false),
            Triple(TlsPolicy(), "localhost", true), Triple(TlsPolicy(), "wrong.example", false))) {
            val server = serverContext.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            server.soTimeout = 4000
            val executor = Executors.newSingleThreadExecutor()
            val job = executor.submit { runCatching { (server.accept() as SSLSocket).use { socket ->
                socket.soTimeout = 4000; socket.startHandshake()
                val data = ByteArray(60_000); java.io.DataInputStream(socket.inputStream).readFully(data)
                socket.outputStream.write(data); socket.outputStream.flush()
            } } }
            try {
                val raw = Socket().apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort), 3000); soTimeout = 4000 }
                val engine = if (policy.isPinned) policy.engine(identity, server.localPort) else trusted.createSSLEngine(identity, server.localPort).apply {
                    useClientMode = true; sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                }
                StreamTlsTransport(SocketTransport(raw), engine).use { stream ->
                    try {
                        stream.handshake(); assertTrue(succeeds)
                        val bytes = ByteArray(60_000) { it.toByte() }; stream.output.write(bytes); stream.output.flush()
                        val reply = ByteArray(bytes.size); java.io.DataInputStream(stream.input).readFully(reply); assertArrayEquals(bytes, reply)
                    } catch (_: SSLException) { assertFalse(succeeds) }
                }
            } finally { server.close(); job.get(5, TimeUnit.SECONDS); executor.shutdownNow() }
        }
    }
    private fun handshake(serverContext: SSLContext, policy: TlsPolicy, expected: Boolean,
                          factory: SSLSocketFactory = policy.socketFactory(), identity: String = "localhost") {
        val server = serverContext.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
        server.soTimeout = 4000
        val executor = Executors.newSingleThreadExecutor()
        val job = executor.submit { runCatching { (server.accept() as SSLSocket).use { it.soTimeout = 4000; it.startHandshake() } } }
        try {
            val raw = Socket().apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort), 3000) }
            (factory.createSocket(raw, identity, server.localPort, true) as SSLSocket).use {
                policy.configure(it); it.soTimeout = 4000
                try { it.startHandshake(); assertTrue("Unexpected TLS acceptance", expected) }
                catch (e: SSLException) { assertFalse("Unexpected TLS rejection", expected) }
            }
        } finally { server.close(); job.get(5, TimeUnit.SECONDS); executor.shutdownNow(); executor.awaitTermination(5, TimeUnit.SECONDS) }
    }
}
