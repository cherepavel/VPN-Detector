package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.util.nowString

object ReportExportFormatter {

    data class ExportInput(
        val report: DetectionReport,
        val nativeDetailsRaw: String,
        val javaTunnelNames: List<String>,
        val installedVpnApps: List<String>,
        val dynamicVpnApps: List<String> = emptyList(),
        val vpnRoutes: List<String> = emptyList(),
        val vpnDnsServers: List<String> = emptyList(),
        val allDnsServers: List<String> = emptyList(),
        val internalDnsServers: List<String> = emptyList(),
        val contextualInternalDnsServers: List<String> = emptyList(),
        val privateDnsActive: Boolean = false,
        val privateDnsServerName: String? = null,
        val activeNetworkNotVpn: Boolean? = null,
        val preferredNetworkNotVpn: Boolean? = null,
        val underlyingNetworksSummary: String? = null,
        val kernelRoutes: List<String> = emptyList(),
        val kernelIpv6Routes: List<String> = emptyList(),
        val tunTypeInterfaces: List<String> = emptyList(),
        val lowMtuInterfaces: List<String> = emptyList(),
        val proxyInfo: String? = null,
        val vpnPermissionGranted: Boolean = false,
        val vpnBandwidthSummary: String? = null,
        val nativeError: String? = null,
        val trackedAppsErrors: Map<String, String> = emptyMap()
    )

    fun buildText(input: ExportInput): String {
        val report = input.report

        return buildString {
            appendLine("VPN Detector Report")
            appendLine("Generated: ${nowString()}")
            appendLine()

            appendLine("=== OVERALL STATUS ===")
            appendLine(report.overallTitle)
            appendLine(report.overallSummary)
            appendLine(report.overallExplanation)
            appendLine()

            appendLine("=== OFFICIAL ANDROID API ===")
            appendLine("TRANSPORT_VPN across all networks: ${report.transportAnyValue}")
            appendLine("TRANSPORT_VPN active network only: ${report.transportActiveValue}")
            appendLine("Transport state: ${report.transportStateText}")
            appendLine("Transport subtitle: ${report.transportSubtitle}")
            appendLine()

            if (report.apiSignals.isNotEmpty()) {
                appendLine("API signals:")
                report.apiSignals.forEach { signal ->
                    appendLine("- ${signal.title}")
                    appendLine("  source: ${signal.source}")
                    appendLine("  value: ${signal.value}")
                    appendLine("  hint: ${signal.hint}")
                }
                appendLine()
            }

            if (input.vpnRoutes.isNotEmpty() || input.vpnDnsServers.isNotEmpty() ||
                input.allDnsServers.isNotEmpty() || input.internalDnsServers.isNotEmpty() ||
                input.contextualInternalDnsServers.isNotEmpty() ||
                input.privateDnsActive || input.privateDnsServerName != null ||
                input.activeNetworkNotVpn != null || input.preferredNetworkNotVpn != null ||
                input.underlyingNetworksSummary != null || input.vpnBandwidthSummary != null) {
                appendLine("=== VPN NETWORK DETAILS ===")
                if (input.vpnRoutes.isNotEmpty()) {
                    appendLine("Routes:")
                    input.vpnRoutes.forEach { appendLine("  $it") }
                }
                if (input.vpnDnsServers.isNotEmpty()) {
                    appendLine("DNS servers: ${input.vpnDnsServers.joinToString(", ")}")
                }
                if (input.allDnsServers.isNotEmpty()) {
                    appendLine("DNS across visible networks:")
                    input.allDnsServers.forEach { appendLine("  $it") }
                }
                if (input.internalDnsServers.isNotEmpty()) {
                    appendLine("Internal/private-range DNS servers:")
                    input.internalDnsServers.forEach { appendLine("  $it") }
                }
                if (input.contextualInternalDnsServers.isNotEmpty()) {
                    appendLine("Cellular private DNS observed (not treated as VPN):")
                    input.contextualInternalDnsServers.forEach { appendLine("  $it") }
                }
                if (input.privateDnsActive || input.privateDnsServerName != null) {
                    appendLine(
                        "Private DNS: " + buildString {
                            append(if (input.privateDnsActive) "active" else "inactive")
                            input.privateDnsServerName?.let { append(" ($it)") }
                        }
                    )
                }
                if (input.activeNetworkNotVpn != null || input.preferredNetworkNotVpn != null) {
                    appendLine(
                        "NET_CAPABILITY_NOT_VPN: active=${input.activeNetworkNotVpn ?: "unknown"}, " +
                            "preferred=${input.preferredNetworkNotVpn ?: "unknown"}"
                    )
                }
                input.underlyingNetworksSummary?.let { appendLine("Underlying networks: $it") }
                input.vpnBandwidthSummary?.let { appendLine("Bandwidth: $it") }
                appendLine()
            }

            if (input.tunTypeInterfaces.isNotEmpty() || input.lowMtuInterfaces.isNotEmpty() ||
                input.kernelRoutes.isNotEmpty() || input.kernelIpv6Routes.isNotEmpty() ||
                input.proxyInfo != null || input.vpnPermissionGranted) {
                appendLine("=== ADDITIONAL SIGNALS ===")
                if (input.tunTypeInterfaces.isNotEmpty()) {
                    appendLine("TUN interfaces (type=65534): ${input.tunTypeInterfaces.joinToString(", ")}")
                }
                if (input.lowMtuInterfaces.isNotEmpty()) {
                    appendLine("Low-MTU interfaces (<1500):")
                    input.lowMtuInterfaces.forEach { appendLine("  $it") }
                }
                if (input.kernelRoutes.isNotEmpty()) {
                    appendLine("Kernel route table (/proc/net/route):")
                    input.kernelRoutes.forEach { appendLine("  $it") }
                }
                if (input.kernelIpv6Routes.isNotEmpty()) {
                    appendLine("Kernel route table (/proc/net/ipv6_route):")
                    input.kernelIpv6Routes.forEach { appendLine("  $it") }
                }
                input.proxyInfo?.let {
                    appendLine("Proxy detected:")
                    it.lines().forEach { line -> appendLine("  $line") }
                }
                if (input.vpnPermissionGranted) {
                    appendLine("VPN permission: this app holds VPN grant (anomalous).")
                }
                appendLine()
            }

            appendLine("=== NATIVE LOW-LEVEL ENUMERATION ===")
            if (input.nativeError != null) {
                appendLine("Error: ${input.nativeError}")
            }
            appendLine("Signal value: ${report.nativeSignal.value}")
            appendLine("Signal hint: ${report.nativeSignal.hint}")
            appendLine()
            appendLine(input.nativeDetailsRaw)
            appendLine()

            appendLine("=== JAVA INTERFACE ENUMERATION ===")
            appendLine("Signal value: ${report.javaSignal.value}")
            appendLine("Signal hint: ${report.javaSignal.hint}")
            if (input.javaTunnelNames.isNotEmpty()) {
                appendLine("Matched tunnel-like names:")
                input.javaTunnelNames.forEach { appendLine("- $it") }
            }
            appendLine()

            appendLine("=== DETECTED VPN APPS ===")
            val dynamicUnknown = input.dynamicVpnApps.filter { pkg ->
                input.installedVpnApps.none { it.contains(pkg) }
            }
            if (input.installedVpnApps.isNotEmpty()) {
                appendLine("From tracked list:")
                input.installedVpnApps.forEach { appendLine("- $it") }
            }
            if (dynamicUnknown.isNotEmpty()) {
                appendLine("Detected via VpnService query:")
                dynamicUnknown.forEach { appendLine("- $it") }
            }
            if (input.trackedAppsErrors.isNotEmpty()) {
                appendLine("Check errors:")
                input.trackedAppsErrors.forEach { (pkg, err) -> appendLine("- $pkg: $err") }
            }
            if (input.installedVpnApps.isEmpty() && dynamicUnknown.isEmpty()) {
                appendLine("No VPN-related apps detected.")
            }
        }.trim()
    }
}
