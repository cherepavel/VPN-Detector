package com.cherepavel.vpndetector.util

import android.net.NetworkCapabilities
import android.os.Build

object TransportInfoFormatter {

    fun summarizeVpnTransportInfo(capabilities: NetworkCapabilities?): String? {
        if (capabilities == null) return null
        if (!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null

        val transportInfo = capabilities.transportInfo ?: return null
        val simpleName = transportInfo.javaClass.simpleName ?: transportInfo.toString()
        val vpnType = readVpnType(transportInfo)
        val text = if (vpnType != null) "$simpleName(type=$vpnType)" else simpleName

        return text
            .takeIf { it.isNotBlank() }
            .takeIf { !it.equals("WifiInfo", ignoreCase = true) }
            .takeIf {
                !it.equals("VcnTransportInfo", ignoreCase = true) ||
                        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
    }

    private fun readVpnType(transportInfo: Any): String? {
        val className = transportInfo.javaClass.name
        if (!className.endsWith("VpnTransportInfo")) return null

        val typeValue = runCatching {
            transportInfo.javaClass.getMethod("getType").invoke(transportInfo) as? Int
        }.getOrNull() ?: return null

        return when (typeValue) {
            1 -> "PLATFORM"
            2 -> "LEGACY"
            3 -> "IKEV2"
            else -> "UNKNOWN:$typeValue"
        }
    }
}
