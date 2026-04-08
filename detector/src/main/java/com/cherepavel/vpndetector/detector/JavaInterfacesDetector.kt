package com.cherepavel.vpndetector.detector

import com.cherepavel.vpndetector.util.toListSafe
import java.net.NetworkInterface

class JavaInterfacesDetector {

    fun detectTunnelNames(): List<String> {
        return try {
            NetworkInterface.getNetworkInterfaces()
                ?.toListSafe()
                ?.mapNotNull { it.name }
                ?.filter { TunnelNameMatcher.looksLikeTunnelName(it) }
                ?.distinct()
                ?.sorted()
                ?: emptyList()
        } catch (_: Throwable) {
            emptyList()
        }
    }
}
