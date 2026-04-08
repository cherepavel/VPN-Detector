package com.cherepavel.vpndetector.detector

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.cherepavel.vpndetector.model.VpnDetectionResult
import com.cherepavel.vpndetector.model.VpnNetworkInfo
import com.cherepavel.vpndetector.util.TransportInfoFormatter

class VpnDetector(
    private val context: Context
) {
    fun detect(): VpnDetectionResult {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        val activeNetwork = cm.activeNetwork
        val activeCaps = activeNetwork?.let(cm::getNetworkCapabilities)

        @Suppress("DEPRECATION")
        val allNetworks = cm.allNetworks.toList()

        val vpnNetworks = allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null

            val linkProps = cm.getLinkProperties(network)

            VpnNetworkInfo(
                interfaceName = linkProps?.interfaceName,
                transports = extractTransports(caps),
                capabilities = extractCapabilities(caps),
                transportInfoSummary = TransportInfoFormatter.summarizeVpnTransportInfo(caps)
            )
        }

        return VpnDetectionResult(
            activeNetworkPresent = activeNetwork != null,
            activeNetworkIsVpn = activeCaps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            anyNetworkHasVpnTransport = vpnNetworks.isNotEmpty(),
            activeNetworkHasInternet = activeCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
            vpnNetworks = vpnNetworks
        )
    }

    private fun extractTransports(caps: NetworkCapabilities): List<String> {
        return buildList {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) add("WIFI")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) add("CELLULAR")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) add("ETHERNET")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) add("BLUETOOTH")
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) add("VPN")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE)) add("WIFI_AWARE")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_USB)) add("USB")
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_THREAD)) add("THREAD")
        }
    }

    private fun extractCapabilities(caps: NetworkCapabilities): List<String> {
        return buildList {
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) add("INTERNET")
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) add("VALIDATED")
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)) add("TRUSTED")
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)) add("NOT_RESTRICTED")
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) add("NOT_VPN")
        }
    }
}
