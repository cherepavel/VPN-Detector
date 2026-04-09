package com.cherepavel.vpndetector.model

enum class DetectionCategory {
    OFFICIAL,
    HEURISTIC,
    APP,
    CONTEXT
}

enum class DetectionConfidence {
    CONFIRMED,
    LIKELY,
    WEAK_SIGNAL,
    NO_EVIDENCE
}

enum class DetectionStatus {
    ACTIVE_VPN,
    SPLIT_TUNNEL,
    VPN_LIKE,
    APPS_PRESENT,
    NO_EVIDENCE
}

data class DetectionEvidence(
    val key: String,
    val category: DetectionCategory,
    val weight: Int,
    val present: Boolean,
    val summary: String
)

data class DetectionAssessment(
    val status: DetectionStatus,
    val confidence: DetectionConfidence,
    val score: Int,
    val evidence: List<DetectionEvidence>
)

data class DetectionSnapshot(
    val hasTransportVpnAny: Boolean,
    val hasTransportVpnActive: Boolean,
    val rawInterfaceName: String?,
    val transportInfoSummary: String?,
    val nativeTunnelNames: List<String>,
    val nativeDetails: List<String>,
    val javaTunnelNames: List<String>,
    val installedVpnApps: List<String>,
    val dynamicVpnApps: List<String>,
    val vpnRoutes: List<String>,
    val vpnDnsServers: List<String>,
    val allDnsServers: List<String>,
    val internalDnsServers: List<String>,
    val contextualInternalDnsServers: List<String>,
    val privateDnsActive: Boolean,
    val privateDnsServerName: String?,
    val activeNetworkNotVpn: Boolean?,
    val preferredNetworkNotVpn: Boolean?,
    val kernelRoutes: List<String>,
    val kernelIpv6Routes: List<String>,
    val tunTypeInterfaces: List<String>,
    val lowMtuInterfaces: List<String>,
    val vpnPermissionGranted: Boolean,
    val vpnBandwidthSummary: String?,
    val nativeError: String?,
    val trackedAppsErrors: Map<String, String>,
    val lockdownLikely: Boolean,
    val knownVpnDnsMatches: List<String>,
    val workProfileCount: Int,
    val isManagedProfile: Boolean,
    val assessment: DetectionAssessment
) {
    val unknownDynamicApps: List<String>
        get() = dynamicVpnApps.filter { pkg -> installedVpnApps.none { it.contains(pkg) } }
}
