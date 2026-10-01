package com.blockto.sevpn

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.blockto.sevpn.storage.VpnProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ProfileViewModel(application: Application) : AndroidViewModel(application) {
    private val repo = (application as SevpnApplication).profiles
    private val mutableProfile = MutableStateFlow(VpnProfile())
    val profile = mutableProfile.asStateFlow()
    val password = MutableStateFlow("") // Deliberately excluded from SavedStateHandle.
    val error = MutableStateFlow<String?>(null)
    val ready = MutableStateFlow(false)
    val saving = MutableStateFlow(false)
    val hasSavedPassword = MutableStateFlow(false)
    private var storedIdentity: String? = null
    init {
        viewModelScope.launch {
            try { mutableProfile.value = repo.load(); storedIdentity = profile.value.identity; hasSavedPassword.value = repo.hasPassword() }
            catch (_: Exception) { error.value = "Could not load the saved profile" }
            finally { ready.value = true }
        }
    }
    fun update(transform: (VpnProfile) -> VpnProfile) { mutableProfile.value = transform(mutableProfile.value); error.value = null }
    fun save(connect: (() -> Unit)? = null) {
        if (saving.value) return
        saving.value = true
        val p = profile.value
        val secret = if (password.value.isEmpty() && hasSavedPassword.value && storedIdentity == p.identity) null else password.value.toCharArray()
        viewModelScope.launch {
            try {
                repo.save(p, secret); password.value = ""; storedIdentity = p.identity; hasSavedPassword.value = repo.hasPassword()
                error.value = null; connect?.invoke()
            } catch (e: IllegalArgumentException) { error.value = e.message ?: "Check the profile settings" }
            catch (_: Exception) { error.value = "Could not save the encrypted profile" }
            finally { secret?.fill('\u0000'); saving.value = false }
        }
    }
}
