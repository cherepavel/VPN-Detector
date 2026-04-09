package com.cherepavel.vpndetector.util

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import com.cherepavel.vpndetector.detector.TunnelNameMatcher
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

data class DnsSignalSummary(
    val allServers: List<String>,
    val internalServers: List<String>,
    val contextualInternalServers: List<String>,
    val privateDnsActive: Boolean,
    val privateDnsServerName: String?
)

data class VpnPolicySummary(
    val activeNetworkNotVpn: Boolean?,
    val preferredNetworkNotVpn: Boolean?
)

object NetworkSignalAnalyzer {

    fun buildDnsSummary(
        connectivityManager: ConnectivityManager,
        networks: List<Network>,
        preferredLinkProperties: LinkProperties?
    ): DnsSignalSummary {
        val labeledServers = linkedSetOf<String>()
        val internalServers = linkedSetOf<String>()
        val contextualInternalServers = linkedSetOf<String>()

        for (network in networks) {
            val linkProperties = connectivityManager.getLinkProperties(network) ?: continue
            val iface = linkProperties.interfaceName ?: network.toString()
            for (address in linkProperties.dnsServers) {
                val hostAddress = address.hostAddress ?: continue
                val labeled = "$iface:$hostAddress"
                labeledServers += labeled
                if (isSuspiciousInternalDnsAddress(iface, address)) {
                    internalServers += labeled
                } else if (isContextualInternalDnsAddress(iface, address)) {
                    contextualInternalServers += labeled
                }
            }
        }

        val privateDnsActive = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            preferredLinkProperties?.isPrivateDnsActive == true
        } else {
            false
        }
        val privateDnsServerName = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            preferredLinkProperties?.privateDnsServerName?.takeIf { it.isNotBlank() }
        } else {
            null
        }

        return DnsSignalSummary(
            allServers = labeledServers.toList(),
            internalServers = internalServers.toList(),
            contextualInternalServers = contextualInternalServers.toList(),
            privateDnsActive = privateDnsActive,
            privateDnsServerName = privateDnsServerName
        )
    }

    fun buildPolicySummary(
        activeCapabilities: NetworkCapabilities?,
        preferredCapabilities: NetworkCapabilities?
    ): VpnPolicySummary {
        return VpnPolicySummary(
            activeNetworkNotVpn = activeCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
            preferredNetworkNotVpn = preferredCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        )
    }

    private fun isSuspiciousInternalDnsAddress(
        interfaceName: String?,
        address: InetAddress
    ): Boolean {
        val iface = interfaceName?.trim().orEmpty()
        if (!isInternalDnsAddress(address)) return false
        if (iface.isBlank()) return false
        if (isLikelyCellularInterface(iface)) return false
        return TunnelNameMatcher.looksLikeTunnelName(iface)
    }

    private fun isContextualInternalDnsAddress(
        interfaceName: String?,
        address: InetAddress
    ): Boolean {
        val iface = interfaceName?.trim().orEmpty()
        if (!isInternalDnsAddress(address)) return false
        if (iface.isBlank()) return false
        return isLikelyCellularInterface(iface)
    }

    private fun isLikelyCellularInterface(interfaceName: String): Boolean {
        val lowered = interfaceName.lowercase()
        return lowered.startsWith("rmnet") ||
            lowered.startsWith("ccmni") ||
            lowered.startsWith("pdp") ||
            lowered.startsWith("v4-rmnet") ||
            lowered.startsWith("vif")
    }

    private fun isInternalDnsAddress(address: InetAddress): Boolean {
        return when (address) {
            is Inet4Address -> {
                val bytes = address.address
                val first = bytes[0].toInt() and 0xFF
                val second = bytes[1].toInt() and 0xFF
                first == 10 ||
                    (first == 172 && second in 16..31) ||
                    (first == 192 && second == 168) ||
                    (first == 100 && second in 64..127)
            }

            is Inet6Address -> {
                val first = address.address[0].toInt() and 0xFE
                first == 0xFC
            }
            else -> false
        }
    }
}
