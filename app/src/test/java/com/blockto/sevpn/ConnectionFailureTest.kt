package com.blockto.sevpn

import com.blockto.sevpn.protocol.SoftEtherServerException
import com.blockto.sevpn.vpn.*
import org.junit.Assert.*
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.ConnectException
import javax.net.ssl.SSLHandshakeException

class ConnectionFailureTest {
    @Test fun socketProtectionFailureIsTerminalAndDistinctFromNetworkLoss() {
        val failed = ConnectionFailures.classify(TransportSetupException(TransportStep.SOCKET_PROTECTION, IOException("synthetic-private-details")), VpnPhase.CONNECTING_TRANSPORT)
        assertEquals(FailureKind.SOCKET_PROTECTION, failed.kind); assertFalse(failed.retry)
        assertEquals(TransportStep.SOCKET_PROTECTION, failed.step)
        assertTrue(failed.message.contains("protect"))
        val changed = ConnectionFailures.classify(UnderlyingNetworkChangedException(), VpnPhase.CONNECTING_TRANSPORT)
        assertEquals(FailureKind.NETWORK_CHANGED, changed.kind); assertTrue(changed.retry)
    }
    @Test fun networkBindingRetainsTheOperationAndSafeNumericErrno() {
        val failure = ConnectionFailures.classify(TransportSetupException(TransportStep.NETWORK_BIND, IOException("synthetic-private-details")), VpnPhase.CONNECTING_TRANSPORT, 101)
        assertEquals(FailureKind.NETWORK_BIND, failure.kind); assertEquals(101, failure.errno); assertTrue(failure.retry)
        val log = DiagnosticLog(); log.failure(failure)
        assertTrue(log.export().contains("operation=NETWORK_BIND errno=101"))
        assertFalse(log.export().contains("synthetic-private-details"))
    }
    @Test fun wrappedTlsValidationErrorsNeverBecomeRetryingGenericIo() {
        val failure = ConnectionFailures.classify(TransportSetupException(TransportStep.TLS_HANDSHAKE, SSLHandshakeException("synthetic-private-details")), VpnPhase.TLS_HANDSHAKE)
        assertEquals(FailureKind.TLS, failure.kind); assertFalse(failure.retry)
    }
    @Test fun tcpAndHelloFailuresKeepTheirStageWithoutExceptionMessages() {
        val tcp = ConnectionFailures.classify(TransportSetupException(TransportStep.TCP_CONNECT, ConnectException("synthetic-private-details")), VpnPhase.CONNECTING_TRANSPORT)
        assertEquals(FailureKind.TCP, tcp.kind); assertTrue(tcp.retry)
        val hello = ConnectionFailures.classify(EOFException("synthetic-private-details"), VpnPhase.SOFTETHER_HANDSHAKE)
        assertEquals(FailureKind.EOF, hello.kind); assertTrue(hello.message.contains("SoftEther hello"))
        val log = DiagnosticLog(); log.failure(tcp); log.failure(hello)
        assertTrue(log.export().contains("stage=SOFTETHER_HANDSHAKE cause=EOF"))
        assertFalse(log.export().contains("synthetic-private-details"))
    }
    @Test fun nativeServerErrorsRetainTheirNumericCode() {
        val failure = ConnectionFailures.classify(SoftEtherServerException(9), VpnPhase.AUTHENTICATING)
        assertEquals(FailureKind.SERVER, failure.kind); assertEquals(9, failure.serverCode); assertFalse(failure.retry)
    }
}
