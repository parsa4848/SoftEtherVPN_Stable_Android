package com.blockto.sevpn

import android.os.ParcelFileDescriptor
import com.blockto.sevpn.vpn.TunnelSocketSetup
import org.junit.Assert.*
import org.junit.Test
import java.net.Socket

class SocketInitializationTest {
    @Test fun androidDescriptorExistsBeforeSocketProtectionBindingOrConnect() {
        Socket().use { socket ->
            TunnelSocketSetup.initialize(socket)
            assertFalse(socket.isConnected)
            assertFalse(socket.isBound)
            // Uses Android's actual descriptor. A JVM Socket mock cannot
            // reproduce the invalid descriptor passed to VpnService.protect.
            ParcelFileDescriptor.fromSocket(socket).use { fd ->
                assertTrue(fd.fileDescriptor.valid())
            }
            assertTrue(socket.tcpNoDelay)
        }
    }
}
