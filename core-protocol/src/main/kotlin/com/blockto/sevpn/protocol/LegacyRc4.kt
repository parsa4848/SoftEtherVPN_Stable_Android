/* SoftEther's legacy RC4 packet primitive, required for R-UDP segments and
 * acceleration v1. TLS remains mandatory over the R-UDP stream. */
package com.blockto.sevpn.protocol

internal fun sha1(vararg parts: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-1").run {
    parts.forEach { update(it) }; digest()
}

internal fun rc4(key: ByteArray, bytes: ByteArray): ByteArray {
    require(key.isNotEmpty())
    val state = IntArray(256) { it }; var j = 0
    for (i in state.indices) {
        j = (j + state[i] + (key[i % key.size].toInt() and 255)) and 255
        val old = state[i]; state[i] = state[j]; state[j] = old
    }
    var i = 0; j = 0
    val result = ByteArray(bytes.size)
    for (n in bytes.indices) {
        i = (i + 1) and 255; j = (j + state[i]) and 255
        val old = state[i]; state[i] = state[j]; state[j] = old
        result[n] = (bytes[n].toInt() xor state[(state[i] + state[j]) and 255]).toByte()
    }
    state.fill(0); return result
}
