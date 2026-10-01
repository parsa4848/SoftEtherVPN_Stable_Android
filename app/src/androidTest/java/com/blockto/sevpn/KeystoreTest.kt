package com.blockto.sevpn

import com.blockto.sevpn.storage.CredentialStore
import org.junit.Assert.*
import org.junit.Test

class KeystoreTest {
    @Test fun passwordEncryptionIsRandomizedAndBoundToProfile() {
        val store = CredentialStore()
        val password = "synthetic-test-only-password".toCharArray()
        val first = store.encrypt(password, "test-profile")
        val second = store.encrypt(password, "test-profile")
        assertNotEquals(first, second)
        assertFalse(first.contains("synthetic-test-only-password"))
        val decoded = store.decrypt(first, "test-profile")
        try { assertArrayEquals(password, decoded) } finally { decoded.fill('\u0000') }
        try { store.decrypt(first, "another-profile"); fail("AAD mismatch accepted") } catch (_: javax.crypto.AEADBadTagException) {}
        password.fill('\u0000')
    }
}
