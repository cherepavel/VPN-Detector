package com.cherepavel.vpndetector.detector

import android.content.Context
import android.net.VpnService

object VpnPermissionDetector {

    /**
     * Returns true if the calling app currently holds Android VPN permission.
     *
     * VpnService.prepare() returns null when the calling app already owns the VPN
     * grant, and an Intent otherwise. For a passive detector app this will almost
     * always be false. A true result means the detector itself was previously
     * granted VPN permission — an anomalous state worth flagging.
     */
    fun isThisAppVpnOwner(context: Context): Boolean {
        return try {
            VpnService.prepare(context) == null
        } catch (_: Throwable) {
            false
        }
    }
}
