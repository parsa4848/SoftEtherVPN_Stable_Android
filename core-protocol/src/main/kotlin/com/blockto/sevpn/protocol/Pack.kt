/* SoftEther wire layout derived from Mayaqua/Pack.c and Memory.c, Apache-2.0.
 * Copyright (c) SoftEther VPN Project. See THIRD_PARTY_NOTICES.md. */
package com.blockto.sevpn.protocol

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Locale

class ProtocolException(message: String) : java.io.IOException(message)

sealed class PackValue(val type: Int) {
    class UInt(val value: Long) : PackValue(0) { init { require(value in 0..0xffffffffL) } }
    class Data(val value: ByteArray) : PackValue(1)
    class Str(val value: String) : PackValue(2)
    class Unicode(val value: String) : PackValue(3)
    class UInt64(val bits: Long) : PackValue(4)
}

class Pack {
    internal val fields = sortedMapOf<String, Pair<String, List<PackValue>>>()
    fun put(name: String, values: List<PackValue>): Pack {
        require(name.length in 1..63 && name.all { it.code in 33..126 })
        require(values.isNotEmpty() && values.size <= 4096 && values.all { it.type == values[0].type })
        fields[name.lowercase(Locale.ROOT)] = name to values
        return this
    }
    fun uint(name: String, value: Long) = put(name, listOf(PackValue.UInt(value)))
    fun bool(name: String, value: Boolean) = uint(name, if (value) 1 else 0)
    fun str(name: String, value: String) = put(name, listOf(PackValue.Str(value)))
    fun data(name: String, value: ByteArray) = put(name, listOf(PackValue.Data(value)))
    fun values(name: String) = fields[name.lowercase(Locale.ROOT)]?.second
    fun int(name: String, default: Long = 0): Long = (values(name)?.firstOrNull() as? PackValue.UInt)?.value ?: default
    fun bool(name: String) = int(name) != 0L
    fun str(name: String): String? = (values(name)?.firstOrNull() as? PackValue.Str)?.value
    fun data(name: String): ByteArray? = (values(name)?.firstOrNull() as? PackValue.Data)?.value
    fun wipe() { fields.values.forEach { (_, vs) -> vs.forEach { if (it is PackValue.Data) it.value.fill(0) } }; fields.clear() }
}

object SoftEtherPackCodec {
    const val MAX_SIZE = 1024 * 1024
    private fun text(s: String): ByteArray {
        require('\u0000' !in s)
        return s.toByteArray(Charsets.UTF_8)
    }
    fun encode(pack: Pack): ByteArray {
        require(pack.fields.size <= 4096)
        val bytes = ByteArrayOutputStream()
        val out = DataOutputStream(bytes)
        out.writeInt(pack.fields.size)
        pack.fields.values.forEach { (name, vs) ->
            val n = name.toByteArray(Charsets.US_ASCII)
            out.writeInt(n.size + 1) // WriteBufStr counts a NUL that is NOT transmitted.
            out.write(n); out.writeInt(vs[0].type); out.writeInt(vs.size)
            vs.forEach { v ->
                when (v) {
                    is PackValue.UInt -> out.writeInt(v.value.toInt())
                    is PackValue.UInt64 -> out.writeLong(v.bits)
                    is PackValue.Data -> { require(v.value.size <= MAX_SIZE); out.writeInt(v.value.size); out.write(v.value) }
                    is PackValue.Str -> { val b = text(v.value); require(b.size <= MAX_SIZE); out.writeInt(b.size); out.write(b) }
                    is PackValue.Unicode -> { val b = text(v.value); require(b.size < MAX_SIZE); out.writeInt(b.size + 1); out.write(b); out.writeByte(0) }
                }
                require(bytes.size() <= MAX_SIZE)
            }
        }
        return bytes.toByteArray()
    }
    fun decode(bytes: ByteArray): Pack {
        if (bytes.size !in 4..MAX_SIZE) throw ProtocolException("PACK size outside bounds")
        val b = ByteBuffer.wrap(bytes)
        fun int(): Int { if (b.remaining() < 4) throw ProtocolException("Truncated PACK"); return b.int }
        fun length(max: Int): Int { val n = int(); if (n < 0 || n > max) throw ProtocolException("PACK length outside bounds"); return n }
        fun take(n: Int): ByteArray { if (n > b.remaining()) throw ProtocolException("Truncated PACK value"); return ByteArray(n).also { b.get(it) } }
        fun utf(bytes2: ByteArray): String = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes2)).toString()
        } catch (_: Exception) { throw ProtocolException("Invalid PACK text") }
        val p = Pack()
        repeat(length(4096)) {
            val nl = length(64)
            if (nl < 2) throw ProtocolException("Invalid PACK name")
            val nb = take(nl - 1)
            if (nb.any { (it.toInt() and 255) !in 33..126 }) throw ProtocolException("Invalid PACK name")
            val name = String(nb, Charsets.US_ASCII)
            if (p.values(name) != null) throw ProtocolException("Duplicate PACK field")
            val type = int()
            if (type !in 0..4) throw ProtocolException("Unknown PACK type")
            val count = length(4096)
            if (count == 0 || count > b.remaining() / 4) throw ProtocolException("Invalid PACK count")
            val vs = ArrayList<PackValue>(count)
            repeat(count) {
                vs += when (type) {
                    0 -> PackValue.UInt(int().toLong() and 0xffffffffL)
                    4 -> { if (b.remaining() < 8) throw ProtocolException("Truncated int64"); PackValue.UInt64(b.long) }
                    1 -> PackValue.Data(take(length(MAX_SIZE)))
                    2 -> { val v = take(length(MAX_SIZE)); if (v.contains(0)) throw ProtocolException("Embedded NUL"); PackValue.Str(utf(v)) }
                    else -> {
                        val v = take(length(MAX_SIZE))
                        if (v.isEmpty() || v.last() != 0.toByte() || v.dropLast(1).contains(0)) throw ProtocolException("Invalid Unicode termination")
                        PackValue.Unicode(utf(v.copyOf(v.size - 1)))
                    }
                }
            }
            p.put(name, vs)
        }
        if (b.hasRemaining()) throw ProtocolException("Trailing PACK bytes")
        return p
    }
}
