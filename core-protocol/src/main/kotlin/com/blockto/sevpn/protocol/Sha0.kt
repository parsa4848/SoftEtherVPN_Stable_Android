/* Kotlin adaptation of MY_SHA0_Transform in SoftEther Mayaqua/Encrypt.c.
 * Copyright 2013 The Android Open Source Project (BSD-3-Clause).
 * Copyright (c) SoftEther VPN Project (Apache-2.0).
 * Full notices and redistribution conditions: THIRD_PARTY_NOTICES.md. */
package com.blockto.sevpn.protocol

import java.nio.ByteBuffer

/** Compatibility-only SHA-0. Never use for new cryptographic designs. */
object Sha0 {
    fun digest(input: ByteArray): ByteArray {
        require(input.size <= 1024 * 1024)
        val padded = ByteArray(((input.size + 9 + 63) / 64) * 64)
        input.copyInto(padded); padded[input.size] = 0x80.toByte()
        ByteBuffer.wrap(padded, padded.size - 8, 8).putLong(input.size.toLong() * 8)
        val h = intArrayOf(0x67452301, 0xefcdab89.toInt(), 0x98badcfe.toInt(), 0x10325476, 0xc3d2e1f0.toInt())
        val w = IntArray(80)
        val b = ByteBuffer.wrap(padded)
        while (b.hasRemaining()) {
            for (t in 0..15) w[t] = b.int
            for (t in 16..79) w[t] = w[t - 3] xor w[t - 8] xor w[t - 14] xor w[t - 16]
            var a = h[0]; var c1 = h[1]; var c2 = h[2]; var d = h[3]; var e = h[4]
            for (t in 0..79) {
                val f = when (t) {
                    in 0..19 -> (d xor (c1 and (c2 xor d))) + 0x5a827999
                    in 20..39 -> (c1 xor c2 xor d) + 0x6ed9eba1
                    in 40..59 -> ((c1 and c2) or (d and (c1 or c2))) + 0x8f1bbcdc.toInt()
                    else -> (c1 xor c2 xor d) + 0xca62c1d6.toInt()
                }
                val tmp = Integer.rotateLeft(a, 5) + e + w[t] + f
                e = d; d = c2; c2 = Integer.rotateLeft(c1, 30); c1 = a; a = tmp
            }
            h[0] += a; h[1] += c1; h[2] += c2; h[3] += d; h[4] += e
        }
        padded.fill(0); w.fill(0)
        return ByteBuffer.allocate(20).also { out -> h.forEach { out.putInt(it) }; h.fill(0) }.array()
    }
}

object SoftEtherAuthenticator {
    fun response(username: String, password: CharArray, challenge: ByteArray): ByteArray {
        require(challenge.size == 20 && username.all { it.code in 32..126 })
        // Upstream StrUpper is ASCII; UTF-8 password bytes match Unix SoftEther.
        val upper = username.map { if (it in 'a'..'z') it.uppercaseChar() else it }.joinToString("").toByteArray(Charsets.US_ASCII)
        val encoded = Charsets.UTF_8.encode(java.nio.CharBuffer.wrap(password))
        val pw = ByteArray(encoded.remaining()).also { encoded.get(it) }
        if (encoded.hasArray()) encoded.array().fill(0)
        val material = pw + upper
        val hash = Sha0.digest(material)
        val challenged = hash + challenge
        return try { Sha0.digest(challenged) } finally { pw.fill(0); material.fill(0); hash.fill(0); challenged.fill(0) }
    }
    fun login(hub: String, username: String, password: CharArray?, challenge: ByteArray): Pack {
        val p = Pack().str("method", "login").str("hubname", hub).str("username", username)
        if (password == null) p.uint("authtype", 0) else p.uint("authtype", 1).data("secure_password", response(username, password, challenge))
        return p
    }
}
