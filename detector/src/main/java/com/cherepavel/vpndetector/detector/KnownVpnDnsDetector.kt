package com.cherepavel.vpndetector.detector

object KnownVpnDnsDetector {

    /**
     * Public/semi-public DNS IPs that are specific to known VPN providers.
     * Internal RFC-1918 addresses (e.g. ProtonVPN's 10.2.0.1) are already caught
     * by NetworkSignalAnalyzer.isSuspiciousInternalDnsAddress and are not listed here.
     */
    private val KNOWN_VPN_DNS: Map<String, String> = mapOf(
        "193.19.108.2"    to "Mullvad",
        "193.19.108.3"    to "Mullvad",
        "185.95.218.42"   to "Mullvad",
        "185.95.218.43"   to "Mullvad",
        "100.100.100.100" to "Tailscale (MagicDNS)",
        "103.86.96.100"   to "NordVPN",
        "103.86.99.100"   to "NordVPN",
        "10.64.0.1"       to "Mullvad (internal)",
    )

    /**
     * Receives labeled DNS entries in "iface:address" format from NetworkSignalAnalyzer
     * and returns matches as "Provider (address)" strings.
     */
    fun detect(labeledDnsServers: List<String>): List<String> {
        return labeledDnsServers
            .mapNotNull { labeled ->
                val address = labeled.substringAfter(':').trim()
                KNOWN_VPN_DNS[address]?.let { provider -> "$provider ($address)" }
            }
            .distinct()
    }
}
