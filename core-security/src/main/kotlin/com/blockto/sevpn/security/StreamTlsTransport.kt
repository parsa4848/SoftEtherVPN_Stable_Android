package com.blockto.sevpn.security

import com.blockto.sevpn.protocol.SoftEtherTransport
import java.io.*
import java.nio.ByteBuffer
import java.nio.Buffer
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.*

/** TLS over arbitrary reliable streams; works without an Android TCP fd.
 * One input owner and one output owner, as for the existing SSLSocket path.
 * The write lock serializes complete TLS records, including KeyUpdate replies. */
class StreamTlsTransport(private val stream: SoftEtherTransport, private val engine: SSLEngine) : SoftEtherTransport {
    override val type get() = stream.type
    override val localAddress get() = stream.localAddress
    override val remoteAddress get() = stream.remoteAddress
    override val peerCertificate get() = engine.session.peerCertificates.firstOrNull()?.encoded
    private val closed = AtomicBoolean()
    private val wrapLock = Any()
    // Compile against Buffer's API1 descriptors, not JDK9 covariant ByteBuffer
    // methods: the core JVM jar is also consumed by Android API26.
    private val encryptedIn = ByteBuffer.allocate(65536).apply { (this as Buffer).flip() }
    private val plainIn = ByteBuffer.allocate(65536).apply { (this as Buffer).flip() }
    private val encryptedOut = ByteBuffer.allocate(65536)
    private val empty = ByteBuffer.allocate(0)
    private fun tasks() { while (true) { val task = engine.delegatedTask ?: break; task.run() } }
    private fun wrap(source: ByteBuffer): SSLEngineResult = synchronized(wrapLock) {
        (encryptedOut as Buffer).clear()
        val result = engine.wrap(source, encryptedOut)
        if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) throw SSLException("TLS record exceeds buffer bound")
        if (result.status == SSLEngineResult.Status.CLOSED) throw EOFException("TLS stream closed")
        if (encryptedOut.position() > 0) {
            stream.output.write(encryptedOut.array(), 0, encryptedOut.position()); stream.output.flush()
        }
        result
    }
    private fun fillEncrypted() {
        encryptedIn.compact()
        if (!encryptedIn.hasRemaining()) throw SSLException("TLS record exceeds buffer bound")
        val n = stream.input.read(encryptedIn.array(), encryptedIn.position(), encryptedIn.remaining())
        if (n < 0) { engine.closeInbound(); throw EOFException("TLS peer closed") }
        (encryptedIn as Buffer).position(encryptedIn.position() + n); (encryptedIn as Buffer).flip()
    }
    private fun unwrap(): SSLEngineResult {
        plainIn.compact()
        val result = engine.unwrap(encryptedIn, plainIn)
        (plainIn as Buffer).flip()
        if (result.status == SSLEngineResult.Status.BUFFER_OVERFLOW) throw SSLException("TLS plaintext exceeds buffer bound")
        if (result.status == SSLEngineResult.Status.CLOSED) throw EOFException("TLS peer closed")
        return result
    }
    fun handshake() {
        try {
            engine.beginHandshake()
            var steps = 0
            while (true) {
                if (++steps > 8192) throw SSLException("TLS handshake exceeds bounds")
                val status = engine.handshakeStatus
                when {
                    status == SSLEngineResult.HandshakeStatus.NEED_TASK -> tasks()
                    status == SSLEngineResult.HandshakeStatus.NEED_WRAP -> wrap(empty)
                    // NEED_UNWRAP_AGAIN is a JDK/DTLS extension absent on older Android.
                    status == SSLEngineResult.HandshakeStatus.NEED_UNWRAP || status.name == "NEED_UNWRAP_AGAIN" -> {
                        val result = unwrap()
                        if (result.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) fillEncrypted()
                    }
                    else -> return
                }
            }
        } catch (e: Throwable) { runCatching { close() }; throw e }
    }
    override val input = object : InputStream() {
        private fun ready() {
            while (!plainIn.hasRemaining()) {
                if (closed.get()) throw EOFException("TLS stream closed")
                val result = unwrap()
                if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) tasks()
                if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) wrap(empty)
                if (result.status == SSLEngineResult.Status.BUFFER_UNDERFLOW) fillEncrypted()
                else if (result.bytesConsumed() == 0 && result.bytesProduced() == 0 && engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) fillEncrypted()
            }
        }
        override fun read(): Int { ready(); return plainIn.get().toInt() and 255 }
        override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
            require(offset >= 0 && length >= 0 && offset <= bytes.size - length)
            if (length == 0) return 0
            ready()
            val n = minOf(length, plainIn.remaining()); plainIn.get(bytes, offset, n); return n
        }
    }
    private val tlsOutput = object : OutputStream() {
        override fun write(value: Int) { write(byteArrayOf(value.toByte())) }
        override fun write(bytes: ByteArray, offset: Int, length: Int) {
            require(offset >= 0 && length >= 0 && offset <= bytes.size - length)
            val source = ByteBuffer.wrap(bytes, offset, length)
            while (source.hasRemaining()) {
                if (closed.get()) throw EOFException("TLS stream closed")
                val result = wrap(source)
                if (result.handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_TASK) tasks()
                if (result.bytesConsumed() == 0) throw SSLException("TLS write made no progress")
            }
        }
    }
    // Match SocketTransport: the native count/length/payload writes are one
    // TLS record at flush, rather than separate records for each integer.
    override val output: OutputStream = BufferedOutputStream(tlsOutput, 32 * 1024)
    override fun setReadTimeout(milliseconds: Int) = stream.setReadTimeout(milliseconds)
    override fun close() { if (closed.compareAndSet(false, true)) { stream.close() } }
}
