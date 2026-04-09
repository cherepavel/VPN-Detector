package com.cherepavel.vpndetector.ui.export

import android.content.Context
import com.cherepavel.vpndetector.BuildConfig
import com.cherepavel.vpndetector.R
import com.cherepavel.vpndetector.detector.TunnelNameMatcher
import com.cherepavel.vpndetector.model.DetectionConfidence
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.model.DetectionStatus
import com.cherepavel.vpndetector.util.nowString

object ReportExportBuilder {

    fun build(
        context: Context,
        snapshot: DetectionSnapshot
    ): ExportReport {
        val sections = buildList {
            add(
                ExportSection(
                    title = "OVERALL STATUS",
                    items = buildOverallItems(snapshot)
                )
            )

            add(
                ExportSection(
                    title = "OFFICIAL ANDROID API",
                    items = buildOfficialApiItems(snapshot)
                )
            )

            buildVpnNetworkDetailsSection(snapshot)?.let { add(it) }
            buildAdditionalSignalsSection(snapshot)?.let { add(it) }
            add(buildNativeSection(snapshot))
            add(buildJavaSection(snapshot))
            add(buildAppsSection(snapshot))
            buildAdvancedSignalsSection(snapshot)?.let { add(it) }
        }

        return ExportReport(
            title = "VPN Detector Report",
            generatedAt = nowString(),
            buildInfo = buildBuildInfo(),
            sourceCodeUrl = context.getString(R.string.repo_url),
            sections = sections
        )
    }

    private fun buildBuildInfo(): String {
        return "${BuildConfig.VERSION_NAME} • ${BuildConfig.GIT_HASH} • ${BuildConfig.BUILD_TYPE}"
    }

    private fun buildOverallItems(snapshot: DetectionSnapshot): List<ExportItem> {
        val overall = buildOverallBlock(snapshot)

        return buildList {
            add(ExportItem.Paragraph(overall.title))
            add(ExportItem.Paragraph(overall.summary))
            add(ExportItem.Paragraph(overall.explanation))
            add(ExportItem.Field("Score", "${snapshot.assessment.score}/100"))
            add(ExportItem.Field("Confidence", confidenceLabel(snapshot.assessment.confidence)))
            add(ExportItem.Field("Status", snapshot.assessment.status.toString()))
        }
    }

    private fun buildOfficialApiItems(snapshot: DetectionSnapshot): List<ExportItem> {
        val anyVpn = snapshot.hasTransportVpnAny
        val activeVpn = snapshot.hasTransportVpnActive
        val interfaceDetected = TunnelNameMatcher.looksLikeTunnelName(snapshot.rawInterfaceName)
        val transportInfoDetected = !snapshot.transportInfoSummary.isNullOrBlank()

        val items = buildList {
            add(
                ExportItem.Field(
                    "TRANSPORT_VPN across all networks",
                    if (anyVpn) "DETECTED" else "NOT DETECTED"
                )
            )
            add(
                ExportItem.Field(
                    "TRANSPORT_VPN active network only",
                    if (activeVpn) "DETECTED" else "NOT DETECTED"
                )
            )

            val overall = buildOverallBlock(snapshot)
            add(ExportItem.Field("Transport state", overall.transportText))
            add(ExportItem.Field("Transport subtitle", overall.transportSubtitle))

            val interfaceHint = when {
                interfaceDetected && activeVpn ->
                    "The interface name itself looks like a tunnel device and matches the active VPN state."
                interfaceDetected && anyVpn ->
                    "The interface name looks tunnel-like and is consistent with a VPN being present somewhere in the system."
                interfaceDetected ->
                    "The interface name looks tunnel-like, but Android does not currently mark the active path as VPN."
                snapshot.rawInterfaceName != null ->
                    "The interface name does not look like a typical VPN or tunnel interface."
                else ->
                    "Android did not expose an interface name for this network."
            }

            val transportInfoHint = when {
                transportInfoDetected && activeVpn ->
                    "Android returned transport info alongside an active VPN transport."
                transportInfoDetected && anyVpn ->
                    "Transport info is present and aligns with a VPN existing somewhere in the network stack."
                transportInfoDetected ->
                    "Transport info is present, but without a direct active VPN transport flag."
                else ->
                    "No VPN-related transport info was exposed here."
            }

            add(ExportItem.Paragraph("API signals:"))
            add(ExportItem.Paragraph("- Interface name"))
            add(ExportItem.Field("source", "LinkProperties.getInterfaceName()"))
            add(ExportItem.Field("value", snapshot.rawInterfaceName ?: "none"))
            add(ExportItem.Field("hint", interfaceHint))

            add(ExportItem.Paragraph("- Transport info"))
            add(ExportItem.Field("source", "NetworkCapabilities.getTransportInfo()"))
            add(
                ExportItem.Field(
                    "value",
                    formatCompactTransportInfo(snapshot.transportInfoSummary) ?: "none"
                )
            )
            add(ExportItem.Field("hint", transportInfoHint))
        }

        return items
    }

    private fun buildVpnNetworkDetailsSection(snapshot: DetectionSnapshot): ExportSection? {
        val items = buildList {
            if (snapshot.vpnRoutes.isNotEmpty()) {
                add(ExportItem.ListBlock("Routes", snapshot.vpnRoutes))
            }

            if (snapshot.vpnDnsServers.isNotEmpty()) {
                add(
                    ExportItem.Field(
                        "DNS servers",
                        snapshot.vpnDnsServers.joinToString(", ")
                    )
                )
            }

            if (snapshot.allDnsServers.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "DNS across visible networks",
                        values = snapshot.allDnsServers
                    )
                )
            }

            if (snapshot.internalDnsServers.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Internal/private-range DNS servers",
                        values = snapshot.internalDnsServers
                    )
                )
            }

            if (snapshot.contextualInternalDnsServers.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Cellular private DNS observed (not treated as VPN)",
                        values = snapshot.contextualInternalDnsServers
                    )
                )
            }

            if (snapshot.privateDnsActive || snapshot.privateDnsServerName != null) {
                val privateDnsValue = buildString {
                    append(if (snapshot.privateDnsActive) "active" else "inactive")
                    snapshot.privateDnsServerName?.let { append(" ($it)") }
                }
                add(ExportItem.Field("Private DNS", privateDnsValue))
            }

            if (snapshot.activeNetworkNotVpn != null || snapshot.preferredNetworkNotVpn != null) {
                add(
                    ExportItem.Field(
                        "NET_CAPABILITY_NOT_VPN",
                        "active=${snapshot.activeNetworkNotVpn ?: "unknown"}, preferred=${snapshot.preferredNetworkNotVpn ?: "unknown"}"
                    )
                )
            }

            snapshot.vpnBandwidthSummary?.let {
                add(ExportItem.Field("Bandwidth", it))
            }
        }

        if (items.isEmpty()) return null

        return ExportSection(
            title = "VPN NETWORK DETAILS",
            items = items
        )
    }

    private fun buildAdditionalSignalsSection(snapshot: DetectionSnapshot): ExportSection? {
        val items = buildList {
            if (snapshot.tunTypeInterfaces.isNotEmpty()) {
                add(
                    ExportItem.Field(
                        "TUN interfaces (type=65534)",
                        snapshot.tunTypeInterfaces.joinToString(", ")
                    )
                )
            }

            if (snapshot.lowMtuInterfaces.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Low-MTU interfaces (<1500)",
                        values = snapshot.lowMtuInterfaces
                    )
                )
            }

            if (snapshot.kernelRoutes.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Kernel route table (/proc/net/route)",
                        values = snapshot.kernelRoutes
                    )
                )
            }

            if (snapshot.kernelIpv6Routes.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Kernel route table (/proc/net/ipv6_route)",
                        values = snapshot.kernelIpv6Routes
                    )
                )
            }

            if (snapshot.vpnPermissionGranted) {
                add(
                    ExportItem.Paragraph(
                        "VPN permission: this app holds VPN grant (anomalous)."
                    )
                )
            }
        }

        if (items.isEmpty()) return null

        return ExportSection(
            title = "ADDITIONAL SIGNALS",
            items = items
        )
    }

    private fun buildNativeSection(snapshot: DetectionSnapshot): ExportSection {
        val nativeValue = snapshot.nativeTunnelNames.ifEmpty { listOf("none") }.joinToString(", ")
        val nativeHint = if (snapshot.nativeTunnelNames.isNotEmpty()) {
            "Native enumeration found interfaces whose names or properties look tunnel-like."
        } else {
            "Native enumeration did not find any tunnel-like interfaces."
        }

        val nativeDetails = buildString {
            if (snapshot.nativeError != null) {
                appendLine("Native detector error: ${snapshot.nativeError}")
                appendLine()
            }
            if (snapshot.nativeDetails.isNotEmpty()) {
                append(snapshot.nativeDetails.joinToString(separator = "\n\n"))
            } else if (snapshot.nativeError == null) {
                append("No interfaces were returned by the native detector.")
            }
        }.trim()

        return ExportSection(
            title = "NATIVE LOW-LEVEL ENUMERATION",
            items = buildList {
                snapshot.nativeError?.let {
                    add(ExportItem.Field("Error", it))
                }
                add(ExportItem.Field("Signal value", nativeValue))
                add(ExportItem.Field("Signal hint", nativeHint))
                add(ExportItem.Paragraph(nativeDetails))
            }
        )
    }

    private fun buildJavaSection(snapshot: DetectionSnapshot): ExportSection {
        val javaValue = snapshot.javaTunnelNames.ifEmpty { listOf("none") }.joinToString(", ")
        val javaHint = if (snapshot.javaTunnelNames.isNotEmpty()) {
            "Java network enumeration found interface names that look like VPN or tunnel interfaces."
        } else {
            "Java network enumeration did not find any tunnel-like interface names."
        }

        return ExportSection(
            title = "JAVA INTERFACE ENUMERATION",
            items = buildList {
                add(ExportItem.Field("Signal value", javaValue))
                add(ExportItem.Field("Signal hint", javaHint))
                if (snapshot.javaTunnelNames.isNotEmpty()) {
                    add(
                        ExportItem.ListBlock(
                            label = "Matched tunnel-like names",
                            values = snapshot.javaTunnelNames
                        )
                    )
                }
            }
        )
    }

    private fun buildAppsSection(snapshot: DetectionSnapshot): ExportSection {
        return ExportSection(
            title = "DETECTED VPN APPS",
            items = buildList {
                if (snapshot.installedVpnApps.isNotEmpty()) {
                    add(
                        ExportItem.ListBlock(
                            label = "From tracked list",
                            values = snapshot.installedVpnApps
                        )
                    )
                }

                if (snapshot.unknownDynamicApps.isNotEmpty()) {
                    add(
                        ExportItem.ListBlock(
                            label = "Detected via VpnService query",
                            values = snapshot.unknownDynamicApps
                        )
                    )
                }

                if (snapshot.trackedAppsErrors.isNotEmpty()) {
                    add(
                        ExportItem.ListBlock(
                            label = "Check errors",
                            values = snapshot.trackedAppsErrors.map { (pkg, err) -> "$pkg: $err" }
                        )
                    )
                }

                if (snapshot.installedVpnApps.isEmpty() && snapshot.unknownDynamicApps.isEmpty()) {
                    add(ExportItem.Paragraph("No VPN-related apps detected."))
                }
            }
        )
    }

    private fun buildAdvancedSignalsSection(snapshot: DetectionSnapshot): ExportSection? {
        val items = buildList {
            if (snapshot.lockdownLikely) {
                add(
                    ExportItem.Paragraph(
                        "Always-on lockdown: likely (no validated non-VPN path exists)."
                    )
                )
            }

            if (snapshot.knownVpnDnsMatches.isNotEmpty()) {
                add(
                    ExportItem.ListBlock(
                        label = "Known VPN provider DNS",
                        values = snapshot.knownVpnDnsMatches
                    )
                )
            }

            if (snapshot.workProfileCount > 1) {
                add(
                    ExportItem.Paragraph(
                        "Work profile: ${snapshot.workProfileCount} user profiles detected. VPN apps in other profiles are not visible."
                    )
                )
            }

            if (snapshot.isManagedProfile) {
                add(ExportItem.Paragraph("Running inside a managed profile."))
            }
        }

        if (items.isEmpty()) return null

        return ExportSection(
            title = "ADVANCED SIGNALS",
            items = items
        )
    }

    private fun buildOverallBlock(snapshot: DetectionSnapshot): OverallBlock {
        val anyVpn = snapshot.hasTransportVpnAny
        val activeVpn = snapshot.hasTransportVpnActive
        val interfaceDetected = TunnelNameMatcher.looksLikeTunnelName(snapshot.rawInterfaceName)
        val transportInfoDetected = !snapshot.transportInfoSummary.isNullOrBlank()
        val dnsDetected = snapshot.internalDnsServers.isNotEmpty()
        val policyDetected =
            snapshot.activeNetworkNotVpn == false || snapshot.preferredNetworkNotVpn == false
        val nativeDetected = snapshot.nativeTunnelNames.isNotEmpty()
        val javaDetected = snapshot.javaTunnelNames.isNotEmpty()
        val appsDetected = snapshot.installedVpnApps.isNotEmpty()

        val scoreText =
            "Confidence: ${confidenceLabel(snapshot.assessment.confidence)} (${snapshot.assessment.score}/100)."

        return when {
            snapshot.assessment.status == DetectionStatus.ACTIVE_VPN || activeVpn -> {
                val lockdownNote = if (snapshot.lockdownLikely) {
                    " Lockdown mode appears active — no non-VPN path is validated."
                } else {
                    ""
                }

                OverallBlock(
                    title = if (snapshot.lockdownLikely) "VPN detected (lockdown)" else "VPN detected",
                    summary = "The active network is explicitly marked as VPN by Android.$lockdownNote",
                    explanation = "This is the strongest signal in the app: Android reports TRANSPORT_VPN on the network currently in use. $scoreText",
                    transportText = "VPN DETECTED",
                    transportSubtitle = "TRANSPORT_VPN is present on the active network."
                )
            }

            snapshot.assessment.status == DetectionStatus.SPLIT_TUNNEL || anyVpn -> {
                OverallBlock(
                    title = "VPN present outside active path",
                    summary = "Android sees a VPN network in the system, but not on the current active network.",
                    explanation = "This often matches bypass or split-tunnel behavior: a VPN exists, but current traffic may not be fully routed through it. $scoreText",
                    transportText = "SPLIT / BYPASS",
                    transportSubtitle = "A VPN-related transport exists system-wide, but it is not the current active path."
                )
            }

            interfaceDetected || transportInfoDetected || dnsDetected || policyDetected -> {
                OverallBlock(
                    title = "VPN-related API signal",
                    summary = "Android APIs still expose VPN-like indicators even though active TRANSPORT_VPN is absent.",
                    explanation = "This is weaker than a direct VPN transport flag, but interface, DNS, or capability signals still suggest VPN-related state in the visible network stack. $scoreText",
                    transportText = "API SIGNAL",
                    transportSubtitle = "No active TRANSPORT_VPN, but Android APIs still expose VPN-related information."
                )
            }

            nativeDetected || javaDetected -> {
                OverallBlock(
                    title = "Low-level tunnel signal",
                    summary = "No primary Android VPN signal was found, but tunnel-like interfaces were still discovered.",
                    explanation = "This usually means only low-level interface heuristics fired. It is useful as an additional hint, but weaker than official Android VPN signals. $scoreText",
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            snapshot.assessment.status == DetectionStatus.APPS_PRESENT || appsDetected -> {
                OverallBlock(
                    title = "Detected VPN apps",
                    summary = "No active VPN network signal was found, but known VPN-related apps are installed on the device.",
                    explanation = "Installed VPN apps do not prove that a VPN is currently active, but they are still a relevant contextual signal. $scoreText",
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            else -> {
                OverallBlock(
                    title = "No VPN detected",
                    summary = "The app did not find any high-level or low-level VPN indicators.",
                    explanation = "Neither official Android network APIs nor interface enumeration produced a VPN-related signal. $scoreText",
                    transportText = "NOT DETECTED",
                    transportSubtitle = "No VPN transport was reported by Android."
                )
            }
        }
    }

    private data class OverallBlock(
        val title: String,
        val summary: String,
        val explanation: String,
        val transportText: String,
        val transportSubtitle: String
    )

    private fun formatCompactTransportInfo(summary: String?): String? {
        if (summary.isNullOrBlank()) return null

        val normalized = summary
            .replace("VpnTransportInfo", "VPN")
            .replace("type=", "")
            .replace("PLATFORM", "platform")
            .replace("(", " (")
            .trim()

        return when {
            normalized.contains("VPN", ignoreCase = true) &&
                    normalized.contains("platform", ignoreCase = true) -> "VPN (platform)"
            normalized.contains("VPN", ignoreCase = true) -> "VPN"
            else -> normalized
        }
    }

    private fun confidenceLabel(confidence: DetectionConfidence): String {
        return when (confidence) {
            DetectionConfidence.CONFIRMED -> "confirmed"
            DetectionConfidence.LIKELY -> "likely"
            DetectionConfidence.WEAK_SIGNAL -> "weak signal"
            DetectionConfidence.NO_EVIDENCE -> "no evidence"
        }
    }
}
