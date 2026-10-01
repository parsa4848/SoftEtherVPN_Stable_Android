package com.blockto.sevpn.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.CharBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class CredentialStore {
    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }
    fun encrypt(secret: CharArray, identity: String): String {
        val b = Charsets.UTF_8.encode(CharBuffer.wrap(secret))
        val plain = ByteArray(b.remaining()).also { b.get(it) }
        if (b.hasArray()) b.array().fill(0)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()); updateAAD(identity.toByteArray()) }
            val encrypted = cipher.doFinal(plain)
            Base64.encodeToString(cipher.iv + encrypted, Base64.NO_WRAP)
        } finally { plain.fill(0) }
    }
    fun decrypt(blob: String, identity: String): CharArray {
        val b = Base64.decode(blob, Base64.NO_WRAP)
        require(b.size in 28..16_384)
        val plain = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b.copyOfRange(0, 12))); updateAAD(identity.toByteArray())
        }.doFinal(b, 12, b.size - 12)
        return try {
            val chars = Charsets.UTF_8.decode(java.nio.ByteBuffer.wrap(plain))
            CharArray(chars.remaining()).also { chars.get(it); if (chars.hasArray()) chars.array().fill('\u0000') }
        } finally { plain.fill(0); b.fill(0) }
    }
    companion object { private const val ALIAS = "sevpn.profile.password.v1" }
}
