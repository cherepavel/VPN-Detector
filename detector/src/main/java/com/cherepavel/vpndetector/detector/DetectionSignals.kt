package com.cherepavel.vpndetector.detector

data class DetectionSignals(
    val activeVpn: Boolean,
    val anyVpn: Boolean,
    val rawInterfaceName: String?,
    val transportInfoSummary: String?,
    val nativeTunnelNames: List<String>,
    val javaTunnelNames: List<String>,
    val installedVpnApps: List<String>,
    val internalDnsServers: List<String>,
    val contextualInternalDnsServers: List<String>,
    val activeNetworkNotVpn: Boolean?,
    val preferredNetworkNotVpn: Boolean?,
    val tunTypeInterfaces: List<String>,
    val lowMtuInterfaces: List<String>,
    val lockdownLikely: Boolean,
    val knownVpnDnsMatches: List<String>
)
