package com.blockto.sevpn

import android.app.Application
import com.blockto.sevpn.storage.VpnProfileRepository

class SevpnApplication : Application() {
    val profiles by lazy { VpnProfileRepository(this) }
}
