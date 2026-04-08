package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.util.nowString

object ReportExportFormatter {

    data class ExportInput(
        val report: DetectionReport,
        val snapshot: DetectionSnapshot
    )

    fun buildText(input: ExportInput): String {
        val report = input.report
        val snapshot = input.snapshot

        return buildString {
            appendLine("VPN Detector Report")
            appendLine("Generated: ${nowString()}")
            appendLine()

            appendLine("=== OVERALL STATUS ===")
            appendLine(report.overallTitle)
            appendLine(report.overallSummary)
            appendLine(report.overallExplanation)
            appendLine("Score: ${snapshot.assessment.score}/100")
            appendLine("Confidence: ${snapshot.assessment.confidence}")
            appendLine("Status: ${snapshot.assessment.status}")
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

            if (snapshot.vpnRoutes.isNotEmpty() || snapshot.vpnDnsServers.isNotEmpty() ||
                snapshot.allDnsServers.isNotEmpty() || snapshot.internalDnsServers.isNotEmpty() ||
                snapshot.contextualInternalDnsServers.isNotEmpty() ||
                snapshot.privateDnsActive || snapshot.privateDnsServerName != null ||
                snapshot.activeNetworkNotVpn != null || snapshot.preferredNetworkNotVpn != null ||
                snapshot.vpnBandwidthSummary != null) {
                appendLine("=== VPN NETWORK DETAILS ===")
                if (snapshot.vpnRoutes.isNotEmpty()) {
                    appendLine("Routes:")
                    snapshot.vpnRoutes.forEach { appendLine("  $it") }
                }
                if (snapshot.vpnDnsServers.isNotEmpty()) {
                    appendLine("DNS servers: ${snapshot.vpnDnsServers.joinToString(", ")}")
                }
                if (snapshot.allDnsServers.isNotEmpty()) {
                    appendLine("DNS across visible networks:")
                    snapshot.allDnsServers.forEach { appendLine("  $it") }
                }
                if (snapshot.internalDnsServers.isNotEmpty()) {
                    appendLine("Internal/private-range DNS servers:")
                    snapshot.internalDnsServers.forEach { appendLine("  $it") }
                }
                if (snapshot.contextualInternalDnsServers.isNotEmpty()) {
                    appendLine("Cellular private DNS observed (not treated as VPN):")
                    snapshot.contextualInternalDnsServers.forEach { appendLine("  $it") }
                }
                if (snapshot.privateDnsActive || snapshot.privateDnsServerName != null) {
                    appendLine(
                        "Private DNS: " + buildString {
                            append(if (snapshot.privateDnsActive) "active" else "inactive")
                            snapshot.privateDnsServerName?.let { append(" ($it)") }
                        }
                    )
                }
                if (snapshot.activeNetworkNotVpn != null || snapshot.preferredNetworkNotVpn != null) {
                    appendLine(
                        "NET_CAPABILITY_NOT_VPN: active=${snapshot.activeNetworkNotVpn ?: "unknown"}, " +
                            "preferred=${snapshot.preferredNetworkNotVpn ?: "unknown"}"
                    )
                }
                snapshot.vpnBandwidthSummary?.let { appendLine("Bandwidth: $it") }
                appendLine()
            }

            if (snapshot.tunTypeInterfaces.isNotEmpty() || snapshot.lowMtuInterfaces.isNotEmpty() ||
                snapshot.kernelRoutes.isNotEmpty() || snapshot.kernelIpv6Routes.isNotEmpty() ||
                snapshot.proxyInfo != null || snapshot.vpnPermissionGranted) {
                appendLine("=== ADDITIONAL SIGNALS ===")
                if (snapshot.tunTypeInterfaces.isNotEmpty()) {
                    appendLine("TUN interfaces (type=65534): ${snapshot.tunTypeInterfaces.joinToString(", ")}")
                }
                if (snapshot.lowMtuInterfaces.isNotEmpty()) {
                    appendLine("Low-MTU interfaces (<1500):")
                    snapshot.lowMtuInterfaces.forEach { appendLine("  $it") }
                }
                if (snapshot.kernelRoutes.isNotEmpty()) {
                    appendLine("Kernel route table (/proc/net/route):")
                    snapshot.kernelRoutes.forEach { appendLine("  $it") }
                }
                if (snapshot.kernelIpv6Routes.isNotEmpty()) {
                    appendLine("Kernel route table (/proc/net/ipv6_route):")
                    snapshot.kernelIpv6Routes.forEach { appendLine("  $it") }
                }
                snapshot.proxyInfo?.let {
                    appendLine("Proxy detected:")
                    it.lines().forEach { line -> appendLine("  $line") }
                }
                if (snapshot.vpnPermissionGranted) {
                    appendLine("VPN permission: this app holds VPN grant (anomalous).")
                }
                appendLine()
            }

            appendLine("=== NATIVE LOW-LEVEL ENUMERATION ===")
            if (snapshot.nativeError != null) {
                appendLine("Error: ${snapshot.nativeError}")
            }
            appendLine("Signal value: ${report.nativeSignal.value}")
            appendLine("Signal hint: ${report.nativeSignal.hint}")
            appendLine()
            appendLine(report.nativeDetails)
            appendLine()

            appendLine("=== JAVA INTERFACE ENUMERATION ===")
            appendLine("Signal value: ${report.javaSignal.value}")
            appendLine("Signal hint: ${report.javaSignal.hint}")
            if (snapshot.javaTunnelNames.isNotEmpty()) {
                appendLine("Matched tunnel-like names:")
                snapshot.javaTunnelNames.forEach { appendLine("- $it") }
            }
            appendLine()

            appendLine("=== DETECTED VPN APPS ===")
            if (snapshot.installedVpnApps.isNotEmpty()) {
                appendLine("From tracked list:")
                snapshot.installedVpnApps.forEach { appendLine("- $it") }
            }
            if (snapshot.unknownDynamicApps.isNotEmpty()) {
                appendLine("Detected via VpnService query:")
                snapshot.unknownDynamicApps.forEach { appendLine("- $it") }
            }
            if (snapshot.trackedAppsErrors.isNotEmpty()) {
                appendLine("Check errors:")
                snapshot.trackedAppsErrors.forEach { (pkg, err) -> appendLine("- $pkg: $err") }
            }
            if (snapshot.installedVpnApps.isEmpty() && snapshot.unknownDynamicApps.isEmpty()) {
                appendLine("No VPN-related apps detected.")
            }

            if (snapshot.lockdownLikely || snapshot.knownVpnDnsMatches.isNotEmpty() ||
                snapshot.localProxies.isNotEmpty() || snapshot.workProfileCount > 1 ||
                snapshot.isManagedProfile) {
                appendLine()
                appendLine("=== ADVANCED SIGNALS ===")
                if (snapshot.lockdownLikely) {
                    appendLine("Always-on lockdown: likely (no validated non-VPN path exists).")
                }
                if (snapshot.knownVpnDnsMatches.isNotEmpty()) {
                    appendLine("Known VPN provider DNS:")
                    snapshot.knownVpnDnsMatches.forEach { appendLine("- $it") }
                }
                if (snapshot.localProxies.isNotEmpty()) {
                    appendLine("Local proxy ports (no VpnService):")
                    snapshot.localProxies.forEach { appendLine("- $it") }
                }
                if (snapshot.workProfileCount > 1) {
                    appendLine("Work profile: ${snapshot.workProfileCount} user profiles detected. VPN apps in other profiles are not visible.")
                }
                if (snapshot.isManagedProfile) {
                    appendLine("Running inside a managed profile.")
                }
            }
        }.trim()
    }
}
