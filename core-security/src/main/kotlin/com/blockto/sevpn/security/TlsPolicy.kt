package com.blockto.sevpn.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

class TlsPolicy(pinHex: String? = null) {
    private val pin = pinHex?.let {
        val clean = it.replace(":", "").replace(" ", "")
        require(clean.matches(Regex("[0-9a-fA-F]{64}"))) { "Certificate pin must be 64 hexadecimal digits" }
        ByteArray(32) { i -> clean.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
    val isPinned: Boolean get() = pin != null
    fun socketFactory(): SSLSocketFactory {
        if (pin == null) return SSLSocketFactory.getDefault() as SSLSocketFactory
        val expected = pin.copyOf()
        val tm = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) { throw CertificateException("Client trust is unsupported") }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                if (chain.isEmpty()) throw CertificateException("Missing server certificate")
                chain[0].checkValidity()
                val actual = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                if (!MessageDigest.isEqual(expected, actual)) throw CertificateException("Configured certificate pin does not match")
            }
        }
        return SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), SecureRandom()) }.socketFactory
    }
    fun configure(socket: SSLSocket) {
        val protocols = socket.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }
        require(protocols.isNotEmpty()) { "TLS 1.2 is required" }
        socket.enabledProtocols = protocols.toTypedArray()
        socket.sslParameters = socket.sslParameters.apply {
            // In explicit pin mode the exact leaf certificate IS the configured identity.
            endpointIdentificationAlgorithm = if (pin == null) "HTTPS" else null
        }
    }
}
