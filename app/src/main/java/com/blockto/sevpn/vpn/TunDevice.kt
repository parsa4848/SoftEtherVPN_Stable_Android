package com.blockto.sevpn.vpn

import android.os.ParcelFileDescriptor
import android.system.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.SendChannel
import java.io.Closeable
import java.io.IOException

/** Android's nonblocking TUN avoids uncancellable FileInputStream.read(). */
class TunDevice(private val parcel: ParcelFileDescriptor, private val mtu: Int) : Closeable {
    private val fd = parcel.fileDescriptor
    private suspend fun ready(events: Int) = withContext(Dispatchers.IO) {
        val poll = StructPollfd().apply { this.fd = this@TunDevice.fd; this.events = events.toShort() }
        while (true) {
            currentCoroutineContext().ensureActive()
            try {
                if (Os.poll(arrayOf(poll), 250) > 0) {
                    if (poll.revents.toInt() and (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0) throw IOException("Android TUN closed")
                    return@withContext
                }
            } catch (e: ErrnoException) { if (e.errno != OsConstants.EINTR) throw IOException("Android TUN poll failed", e) }
        }
    }
    suspend fun readPackets(outgoing: SendChannel<ByteArray>, started: CompletableDeferred<Unit>) = withContext(Dispatchers.IO) {
        val buffer = ByteArray(mtu + 1)
        started.complete(Unit)
        while (isActive) {
            ready(OsConstants.POLLIN)
            try {
                val n = Os.read(fd, buffer, 0, buffer.size)
                if (n <= 0) throw IOException("Android TUN ended")
                if (n <= mtu) outgoing.send(buffer.copyOf(n))
            } catch (e: ErrnoException) { if (e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) throw IOException("Android TUN read failed", e) }
        }
    }
    suspend fun writePacket(packet: ByteArray) = withContext(Dispatchers.IO) {
        require(packet.size in 20..mtu)
        withTimeout(5000) {
            while (true) {
                currentCoroutineContext().ensureActive()
                try {
                    val n = Os.write(fd, packet, 0, packet.size)
                    if (n != packet.size) throw IOException("Partial Android TUN packet write")
                    break
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN) ready(OsConstants.POLLOUT)
                    else if (e.errno != OsConstants.EINTR) throw IOException("Android TUN write failed", e)
                }
            }
        }
    }
    override fun close() { parcel.close() }
}
