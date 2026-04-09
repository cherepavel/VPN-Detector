package com.cherepavel.vpndetector.detector

import android.net.ConnectivityManager
import android.net.NetworkCapabilities

object AlwaysOnVpnDetector {

    data class Result(
        val lockdownLikely: Boolean,
        val summary: String?
    )

    fun detect(connectivityManager: ConnectivityManager): Result {
        @Suppress("DEPRECATION")
        val allNetworks = connectivityManager.allNetworks
        val capsList = allNetworks.mapNotNull { connectivityManager.getNetworkCapabilities(it) }

        val hasVpnNetwork = capsList.any { it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }

        // Under lockdown: VPN is present but every validated path has TRANSPORT_VPN
        // (non-VPN paths either don't exist or lost VALIDATED capability).
        val hasValidatedNonVpnPath = capsList.any { caps ->
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }

        val lockdownLikely = hasVpnNetwork && !hasValidatedNonVpnPath

        return Result(
            lockdownLikely = lockdownLikely,
            summary = if (lockdownLikely) {
                "VPN present and no validated non-VPN path exists — lockdown mode likely."
            } else null
        )
    }
}
