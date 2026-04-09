package com.cherepavel.vpndetector.detector

import com.cherepavel.vpndetector.model.DetectionAssessment
import com.cherepavel.vpndetector.model.DetectionCategory
import com.cherepavel.vpndetector.model.DetectionConfidence
import com.cherepavel.vpndetector.model.DetectionEvidence
import com.cherepavel.vpndetector.model.DetectionStatus

object DetectionScorer {

    fun assess(signals: DetectionSignals): DetectionAssessment {
        val interfaceDetected = TunnelNameMatcher.looksLikeTunnelName(signals.rawInterfaceName)
        val transportInfoDetected = !signals.transportInfoSummary.isNullOrBlank()

        val evidence = listOf(
            DetectionEvidence(
                key = "active_transport_vpn",
                category = DetectionCategory.OFFICIAL,
                weight = 100,
                present = signals.activeVpn,
                summary = "Android marks the active network with TRANSPORT_VPN."
            ),
            DetectionEvidence(
                key = "background_transport_vpn",
                category = DetectionCategory.OFFICIAL,
                weight = 70,
                present = signals.anyVpn && !signals.activeVpn,
                summary = "Android sees a VPN network, but not on the current active path."
            ),
            DetectionEvidence(
                key = "tunnel_like_interface",
                category = DetectionCategory.HEURISTIC,
                weight = 25,
                present = interfaceDetected,
                summary = "LinkProperties exposed a tunnel-like interface name."
            ),
            DetectionEvidence(
                key = "vpn_transport_info",
                category = DetectionCategory.HEURISTIC,
                weight = 25,
                present = transportInfoDetected,
                summary = "NetworkCapabilities exposed VPN-related transport info."
            ),
            DetectionEvidence(
                key = "native_tunnel_interfaces",
                category = DetectionCategory.HEURISTIC,
                weight = 30,
                present = signals.nativeTunnelNames.isNotEmpty(),
                summary = "Native getifaddrs() found tunnel-like interfaces."
            ),
            DetectionEvidence(
                key = "java_tunnel_interfaces",
                category = DetectionCategory.HEURISTIC,
                weight = 20,
                present = signals.javaTunnelNames.isNotEmpty(),
                summary = "Java NetworkInterface enumeration found tunnel-like interfaces."
            ),
            DetectionEvidence(
                key = "internal_dns_on_tunnel",
                category = DetectionCategory.HEURISTIC,
                weight = 25,
                present = signals.internalDnsServers.isNotEmpty(),
                summary = "Internal/private DNS servers were observed on tunnel-like interfaces."
            ),
            DetectionEvidence(
                key = "not_vpn_capability_cleared",
                category = DetectionCategory.HEURISTIC,
                weight = 15,
                present = signals.activeNetworkNotVpn == false || signals.preferredNetworkNotVpn == false,
                summary = "At least one inspected network cleared NET_CAPABILITY_NOT_VPN."
            ),
            DetectionEvidence(
                key = "tun_interface_type",
                category = DetectionCategory.HEURISTIC,
                weight = 15,
                present = signals.tunTypeInterfaces.isNotEmpty(),
                summary = "A Linux TUN interface type was observed."
            ),
            DetectionEvidence(
                key = "low_mtu_interface",
                category = DetectionCategory.CONTEXT,
                weight = 5,
                present = signals.lowMtuInterfaces.isNotEmpty(),
                summary = "A low-MTU interface was observed."
            ),
            DetectionEvidence(
                key = "installed_vpn_apps",
                category = DetectionCategory.APP,
                weight = 10,
                present = signals.installedVpnApps.isNotEmpty(),
                summary = "Known VPN-related apps are installed on the device."
            ),
            DetectionEvidence(
                key = "carrier_private_dns_context",
                category = DetectionCategory.CONTEXT,
                weight = 0,
                present = signals.contextualInternalDnsServers.isNotEmpty(),
                summary = "Carrier private DNS was observed on a cellular interface and is context only."
            ),
            DetectionEvidence(
                key = "lockdown_likely",
                category = DetectionCategory.HEURISTIC,
                weight = 30,
                present = signals.lockdownLikely,
                summary = "VPN present and no validated non-VPN path exists — always-on lockdown likely."
            ),
            DetectionEvidence(
                key = "known_vpn_dns",
                category = DetectionCategory.HEURISTIC,
                weight = 20,
                present = signals.knownVpnDnsMatches.isNotEmpty(),
                summary = "DNS servers matching known VPN provider addresses were observed."
            ),
        )

        val score = evidence.filter { it.present }.sumOf { it.weight }.coerceAtMost(100)
        val status = when {
            signals.activeVpn -> DetectionStatus.ACTIVE_VPN
            signals.anyVpn -> DetectionStatus.SPLIT_TUNNEL
            score >= 35 -> DetectionStatus.VPN_LIKE
            signals.installedVpnApps.isNotEmpty() -> DetectionStatus.APPS_PRESENT
            else -> DetectionStatus.NO_EVIDENCE
        }
        val confidence = when (status) {
            DetectionStatus.ACTIVE_VPN -> DetectionConfidence.CONFIRMED
            DetectionStatus.SPLIT_TUNNEL -> DetectionConfidence.LIKELY
            DetectionStatus.VPN_LIKE -> DetectionConfidence.LIKELY
            DetectionStatus.APPS_PRESENT -> DetectionConfidence.WEAK_SIGNAL
            DetectionStatus.NO_EVIDENCE ->
                if (score > 0) DetectionConfidence.WEAK_SIGNAL else DetectionConfidence.NO_EVIDENCE
        }

        return DetectionAssessment(
            status = status,
            confidence = confidence,
            score = score,
            evidence = evidence
        )
    }
}
