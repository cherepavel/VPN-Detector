package com.cherepavel.vpndetector.detector

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.util.NetworkSignalAnalyzer
import com.cherepavel.vpndetector.util.TransportInfoFormatter

class DetectionEngine(
    private val context: Context,
    private val connectivityManager: ConnectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
    private val javaInterfacesDetector: JavaInterfacesDetector = JavaInterfacesDetector(),
    private val trackedAppsDetector: TrackedAppsDetector = TrackedAppsDetector(context),
    private val dynamicVpnAppsDetector: DynamicVpnAppsDetector = DynamicVpnAppsDetector(context),
    private val proxyDetector: ProxyDetector = ProxyDetector(context)
) {

    fun detect(): DetectionSnapshot {
        @Suppress("DEPRECATION")
        val allNetworks = connectivityManager.allNetworks.orEmpty()
        val activeNetwork = connectivityManager.activeNetwork
        val activeCapabilities = activeNetwork?.let(connectivityManager::getNetworkCapabilities)

        val vpnNetworks = allNetworks.filter { hasTransportVpn(it) }
        val anyVpn = vpnNetworks.isNotEmpty()
        val activeVpn = activeCapabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true

        val preferredNetwork = vpnNetworks.firstOrNull() ?: activeNetwork ?: allNetworks.firstOrNull()
        val preferredLinkProperties: LinkProperties? =
            preferredNetwork?.let(connectivityManager::getLinkProperties)
        val preferredCapabilities: NetworkCapabilities? =
            preferredNetwork?.let(connectivityManager::getNetworkCapabilities)

        val rawInterfaceName = preferredLinkProperties?.interfaceName
        val transportInfoSummary =
            TransportInfoFormatter.summarizeVpnTransportInfo(preferredCapabilities)

        val vpnNetwork = vpnNetworks.firstOrNull()
        val vpnLinkProps = vpnNetwork?.let(connectivityManager::getLinkProperties)
        val vpnCaps = vpnNetwork?.let(connectivityManager::getNetworkCapabilities)

        val vpnRoutes = vpnLinkProps?.routes?.map { route ->
            buildString {
                append(route.destination.toString())
                route.gateway?.hostAddress?.let { gw -> append(" via $gw") }
                if (route.destination.prefixLength == 0) append(" [DEFAULT]")
            }
        } ?: emptyList()

        val vpnDnsServers = vpnLinkProps?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList()
        val kernelIpv6Routes = IfconfigTermuxLikeDetector.detectKernelIpv6Routes()
        val dnsSummary = NetworkSignalAnalyzer.buildDnsSummary(
            connectivityManager = connectivityManager,
            networks = allNetworks.toList(),
            preferredLinkProperties = preferredLinkProperties
        )
        val policySummary = NetworkSignalAnalyzer.buildPolicySummary(
            activeCapabilities = activeCapabilities,
            preferredCapabilities = preferredCapabilities
        )

        val nativeResult = IfconfigTermuxLikeDetector.detect()
        val kernelRoutes = IfconfigTermuxLikeDetector.detectKernelRoutes()
        val javaTunnelNames = javaInterfacesDetector.detectTunnelNames()

        val trackedResult = trackedAppsDetector.detect()
        val installedVpnApps = trackedResult.installed.map { "${it.label} (${it.packageName})" }
        val dynamicVpnApps = dynamicVpnAppsDetector.detect()

        val mtuRegex = Regex("mtu (\\d+)")
        val typeRegex = Regex("type (\\d+)")
        val tunTypeInterfaces = nativeResult.allInterfaces.mapNotNull { block ->
            val firstLine = block.lineSequence().firstOrNull() ?: return@mapNotNull null
            val type = typeRegex.find(firstLine)?.groupValues?.get(1)?.toIntOrNull()
            if (type == 65534) firstLine.substringBefore(':').trim() else null
        }
        val lowMtuInterfaces = nativeResult.allInterfaces.mapNotNull { block ->
            val firstLine = block.lineSequence().firstOrNull() ?: return@mapNotNull null
            val name = firstLine.substringBefore(':').trim()
            val mtu = mtuRegex.find(firstLine)?.groupValues?.get(1)?.toIntOrNull()
            val type = typeRegex.find(firstLine)?.groupValues?.get(1)?.toIntOrNull()
            if (mtu != null && mtu < 1500 && type != 772 && name != "lo") "$name: mtu $mtu" else null
        }

        val proxyInfo = proxyDetector.detect().summary()
        val vpnPermissionGranted = VpnPermissionDetector.isThisAppVpnOwner(context)
        val vpnBandwidthSummary = vpnCaps?.let { caps ->
            val down = caps.linkDownstreamBandwidthKbps
            val up = caps.linkUpstreamBandwidthKbps
            if (down > 0 || up > 0) "↓ $down Kbps  ↑ $up Kbps" else null
        }

        val nativeTunnelNames = nativeResult.matchedInterfaces
            .map { it.substringBefore(':').trim() }
            .distinct()

        val assessment = DetectionScorer.assess(
            DetectionSignals(
                activeVpn = activeVpn,
                anyVpn = anyVpn,
                rawInterfaceName = rawInterfaceName,
                transportInfoSummary = transportInfoSummary,
                nativeTunnelNames = nativeTunnelNames,
                javaTunnelNames = javaTunnelNames,
                installedVpnApps = installedVpnApps,
                internalDnsServers = dnsSummary.internalServers,
                contextualInternalDnsServers = dnsSummary.contextualInternalServers,
                activeNetworkNotVpn = policySummary.activeNetworkNotVpn,
                preferredNetworkNotVpn = policySummary.preferredNetworkNotVpn,
                tunTypeInterfaces = tunTypeInterfaces,
                lowMtuInterfaces = lowMtuInterfaces,
                proxyInfo = proxyInfo
            )
        )

        return DetectionSnapshot(
            hasTransportVpnAny = anyVpn,
            hasTransportVpnActive = activeVpn,
            rawInterfaceName = rawInterfaceName,
            transportInfoSummary = transportInfoSummary,
            nativeTunnelNames = nativeTunnelNames,
            nativeDetails = nativeResult.allInterfaces,
            javaTunnelNames = javaTunnelNames,
            installedVpnApps = installedVpnApps,
            dynamicVpnApps = dynamicVpnApps,
            vpnRoutes = vpnRoutes,
            vpnDnsServers = vpnDnsServers,
            allDnsServers = dnsSummary.allServers,
            internalDnsServers = dnsSummary.internalServers,
            contextualInternalDnsServers = dnsSummary.contextualInternalServers,
            privateDnsActive = dnsSummary.privateDnsActive,
            privateDnsServerName = dnsSummary.privateDnsServerName,
            activeNetworkNotVpn = policySummary.activeNetworkNotVpn,
            preferredNetworkNotVpn = policySummary.preferredNetworkNotVpn,
            kernelRoutes = kernelRoutes,
            kernelIpv6Routes = kernelIpv6Routes,
            tunTypeInterfaces = tunTypeInterfaces,
            lowMtuInterfaces = lowMtuInterfaces,
            proxyInfo = proxyInfo,
            vpnPermissionGranted = vpnPermissionGranted,
            vpnBandwidthSummary = vpnBandwidthSummary,
            nativeError = nativeResult.nativeError,
            trackedAppsErrors = trackedResult.errors,
            assessment = assessment
        )
    }

    private fun hasTransportVpn(network: Network): Boolean {
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}
