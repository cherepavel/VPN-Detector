package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.detector.TunnelNameMatcher
import com.cherepavel.vpndetector.model.DetectionConfidence
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.model.DetectionStatus

data class DetectionReport(
    val overallTitle: String,
    val overallSummary: String,
    val overallExplanation: String,
    val overallState: SignalState,

    val transportCardState: SignalState,
    val transportStateText: String,
    val transportSubtitle: String,
    val transportAnyValue: String,
    val transportActiveValue: String,
    val transportAnyDetected: Boolean,
    val transportActiveDetected: Boolean,

    val apiSignals: List<SignalItem>,
    val nativeSignal: SignalItem,
    val nativeDetails: String,
    val javaSignal: SignalItem,
    val knownAppsText: String
)

object ReportFormatter {

    fun build(snapshot: DetectionSnapshot): DetectionReport {
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

        val overall = buildOverallBlock(
            snapshot = snapshot,
            activeVpn = activeVpn,
            anyVpn = anyVpn,
            interfaceDetected = interfaceDetected,
            transportInfoDetected = transportInfoDetected,
            dnsDetected = dnsDetected,
            policyDetected = policyDetected,
            nativeDetected = nativeDetected,
            javaDetected = javaDetected,
            appsDetected = appsDetected
        )

        val apiSignals = buildApiSignals(
            rawInterfaceName = snapshot.rawInterfaceName,
            interfaceDetected = interfaceDetected,
            transportInfoSummary = snapshot.transportInfoSummary,
            transportInfoDetected = transportInfoDetected,
            allDnsServers = snapshot.allDnsServers,
            internalDnsServers = snapshot.internalDnsServers,
            contextualInternalDnsServers = snapshot.contextualInternalDnsServers,
            privateDnsActive = snapshot.privateDnsActive,
            privateDnsServerName = snapshot.privateDnsServerName,
            activeNetworkNotVpn = snapshot.activeNetworkNotVpn,
            preferredNetworkNotVpn = snapshot.preferredNetworkNotVpn,
            activeVpn = activeVpn,
            anyVpn = anyVpn
        )

        val nativeSignal = SignalItem(
            title = "Tunnel-like interfaces",
            source = "Native getifaddrs() enumeration",
            value = snapshot.nativeTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
            state = if (nativeDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (nativeDetected) {
                "Native enumeration found interfaces whose names or properties look tunnel-like."
            } else {
                "Native enumeration did not find any tunnel-like interfaces."
            }
        )

        val javaSignal = SignalItem(
            title = "Tunnel-like interfaces",
            source = "Java NetworkInterface enumeration",
            value = snapshot.javaTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
            state = if (javaDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (javaDetected) {
                "Java network enumeration found interface names that look like VPN or tunnel interfaces."
            } else {
                "Java network enumeration did not find any tunnel-like interface names."
            }
        )

        val nativeDetailsText = buildString {
            if (snapshot.nativeError != null) {
                appendLine("Native detector error: ${snapshot.nativeError}")
                appendLine()
            }
            if (snapshot.nativeDetails.isNotEmpty()) {
                append(snapshot.nativeDetails.joinToString(separator = "\n\n"))
            } else if (snapshot.nativeError == null) {
                append("No interfaces were returned by the native detector.")
            }
            if (snapshot.tunTypeInterfaces.isNotEmpty()) {
                append("\n\n--- TUN interfaces (type=65534) ---\n")
                append(snapshot.tunTypeInterfaces.joinToString(", "))
            }
            if (snapshot.lowMtuInterfaces.isNotEmpty()) {
                append("\n\n--- Low-MTU interfaces (<1500) ---\n")
                append(snapshot.lowMtuInterfaces.joinToString("\n"))
            }
            if (snapshot.vpnRoutes.isNotEmpty()) {
                append("\n\n--- VPN network routes ---\n")
                append(snapshot.vpnRoutes.joinToString("\n"))
            }
            if (snapshot.vpnDnsServers.isNotEmpty()) {
                append("\n\n--- VPN DNS servers ---\n")
                append(snapshot.vpnDnsServers.joinToString(", "))
            }
            if (snapshot.allDnsServers.isNotEmpty()) {
                append("\n\n--- DNS servers across visible networks ---\n")
                append(snapshot.allDnsServers.joinToString("\n"))
            }
            if (snapshot.internalDnsServers.isNotEmpty()) {
                append("\n\n--- Internal/private-range DNS servers ---\n")
                append(snapshot.internalDnsServers.joinToString("\n"))
            }
            if (snapshot.contextualInternalDnsServers.isNotEmpty()) {
                append("\n\n--- Cellular private DNS observed (not treated as VPN) ---\n")
                append(snapshot.contextualInternalDnsServers.joinToString("\n"))
            }
            if (snapshot.privateDnsActive || snapshot.privateDnsServerName != null) {
                append("\n\n--- Private DNS ---\n")
                append(
                    buildString {
                        append(if (snapshot.privateDnsActive) "active" else "inactive")
                        snapshot.privateDnsServerName?.let { append(" ($it)") }
                    }
                )
            }
            if (snapshot.activeNetworkNotVpn != null || snapshot.preferredNetworkNotVpn != null) {
                append("\n\n--- NET_CAPABILITY_NOT_VPN ---\n")
                append("active=")
                append(snapshot.activeNetworkNotVpn?.toString() ?: "unknown")
                append(", preferred=")
                append(snapshot.preferredNetworkNotVpn?.toString() ?: "unknown")
            }
            if (snapshot.vpnBandwidthSummary != null) {
                append("\n\n--- VPN bandwidth ---\n")
                append(snapshot.vpnBandwidthSummary)
            }
            if (snapshot.kernelRoutes.isNotEmpty()) {
                append("\n\n--- Kernel route table (/proc/net/route) ---\n")
                append(snapshot.kernelRoutes.joinToString("\n"))
            }
            if (snapshot.kernelIpv6Routes.isNotEmpty()) {
                append("\n\n--- Kernel route table (/proc/net/ipv6_route) ---\n")
                append(snapshot.kernelIpv6Routes.joinToString("\n"))
            }
            if (snapshot.proxyInfo != null) {
                append("\n\n--- Proxy detection ---\n")
                append(snapshot.proxyInfo)
            }
            if (snapshot.vpnPermissionGranted) {
                append("\n\n--- VPN permission ---\n")
                append("This app holds Android VPN permission (anomalous for a detector).")
            }
            if (snapshot.lockdownLikely) {
                append("\n\n--- Always-on / lockdown ---\n")
                append("VPN present and no validated non-VPN path exists. Lockdown mode is likely active.")
            }
            if (snapshot.knownVpnDnsMatches.isNotEmpty()) {
                append("\n\n--- Known VPN provider DNS ---\n")
                append(snapshot.knownVpnDnsMatches.joinToString("\n"))
            }
            if (snapshot.localProxies.isNotEmpty()) {
                append("\n\n--- Local proxy ports (no VpnService) ---\n")
                append(snapshot.localProxies.joinToString("\n"))
            }
            if (snapshot.workProfileCount > 1 || snapshot.isManagedProfile) {
                append("\n\n--- Work / managed profile ---\n")
                if (snapshot.isManagedProfile) {
                    append("Running inside a managed profile.\n")
                }
                if (snapshot.workProfileCount > 1) {
                    append("${snapshot.workProfileCount} user profiles detected. VPN apps in other profiles are not visible to this detector.")
                }
            }
        }

        val appsText = buildString {
            if (snapshot.installedVpnApps.isEmpty() && snapshot.unknownDynamicApps.isEmpty()) {
                append("No VPN-related apps detected.")
            } else {
                snapshot.installedVpnApps.forEach { appendLine("• $it") }
                if (snapshot.unknownDynamicApps.isNotEmpty()) {
                    if (snapshot.installedVpnApps.isNotEmpty()) appendLine()
                    appendLine("Detected via VpnService query:")
                    snapshot.unknownDynamicApps.forEach { appendLine("• $it") }
                }
            }
            if (snapshot.trackedAppsErrors.isNotEmpty()) {
                if (snapshot.installedVpnApps.isNotEmpty() || snapshot.unknownDynamicApps.isNotEmpty()) appendLine()
                appendLine("Check errors (package manager returned unexpected error):")
                snapshot.trackedAppsErrors.forEach { (pkg, err) -> appendLine("• $pkg: $err") }
            }
        }.trimEnd()

        return DetectionReport(
            overallTitle = overall.title,
            overallSummary = overall.summary,
            overallExplanation = overall.explanation,
            overallState = overall.state,

            transportCardState = overall.transportState,
            transportStateText = overall.transportText,
            transportSubtitle = overall.transportSubtitle,
            transportAnyValue = if (anyVpn) "DETECTED" else "NOT DETECTED",
            transportActiveValue = if (activeVpn) "DETECTED" else "NOT DETECTED",
            transportAnyDetected = anyVpn,
            transportActiveDetected = activeVpn,

            apiSignals = apiSignals,
            nativeSignal = nativeSignal,
            nativeDetails = nativeDetailsText,
            javaSignal = javaSignal,
            knownAppsText = appsText
        )
    }

    private fun buildOverallBlock(
        snapshot: DetectionSnapshot,
        activeVpn: Boolean,
        anyVpn: Boolean,
        interfaceDetected: Boolean,
        transportInfoDetected: Boolean,
        dnsDetected: Boolean,
        policyDetected: Boolean,
        nativeDetected: Boolean,
        javaDetected: Boolean,
        appsDetected: Boolean
    ): OverallBlock {
        val confidenceText = snapshot.assessment.confidence.label()
        val scoreText = "Confidence: $confidenceText (${snapshot.assessment.score}/100)."
        return when {
            snapshot.assessment.status == DetectionStatus.ACTIVE_VPN || activeVpn -> {
                val lockdownNote = if (snapshot.lockdownLikely) " Lockdown mode appears active — no non-VPN path is validated." else ""
                OverallBlock(
                    title = if (snapshot.lockdownLikely) "VPN detected (lockdown)" else "VPN detected",
                    summary = "The active network is explicitly marked as VPN by Android.$lockdownNote",
                    explanation = "This is the strongest signal in the app: Android reports TRANSPORT_VPN on the network currently in use. $scoreText",
                    state = SignalState.POSITIVE,
                    transportState = SignalState.POSITIVE,
                    transportText = "VPN DETECTED",
                    transportSubtitle = "TRANSPORT_VPN is present on the active network."
                )
            }

            snapshot.assessment.status == DetectionStatus.SPLIT_TUNNEL || anyVpn -> {
                OverallBlock(
                    title = "VPN present outside active path",
                    summary = "Android sees a VPN network in the system, but not on the current active network.",
                    explanation = "This often matches bypass or split-tunnel behavior: a VPN exists, but current traffic may not be fully routed through it. $scoreText",
                    state = SignalState.SEMI,
                    transportState = SignalState.SEMI,
                    transportText = "SPLIT / BYPASS",
                    transportSubtitle = "A VPN-related transport exists system-wide, but it is not the current active path."
                )
            }

            interfaceDetected || transportInfoDetected || dnsDetected || policyDetected -> {
                OverallBlock(
                    title = "VPN-related API signal",
                    summary = "Android APIs still expose VPN-like indicators even though active TRANSPORT_VPN is absent.",
                    explanation = "This is weaker than a direct VPN transport flag, but interface, DNS, or capability signals still suggest VPN-related state in the visible network stack. $scoreText",
                    state = SignalState.WARNING,
                    transportState = SignalState.WARNING,
                    transportText = "API SIGNAL",
                    transportSubtitle = "No active TRANSPORT_VPN, but Android APIs still expose VPN-related information."
                )
            }

            nativeDetected || javaDetected -> {
                OverallBlock(
                    title = "Low-level tunnel signal",
                    summary = "No primary Android VPN signal was found, but tunnel-like interfaces were still discovered.",
                    explanation = "This usually means only low-level interface heuristics fired. It is useful as an additional hint, but weaker than official Android VPN signals. $scoreText",
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            snapshot.assessment.status == DetectionStatus.APPS_PRESENT || appsDetected -> {
                OverallBlock(
                    title = "Detected VPN apps",
                    summary = "No active VPN network signal was found, but known VPN-related apps are installed on the device.",
                    explanation = "Installed VPN apps do not prove that a VPN is currently active, but they are still a relevant contextual signal. $scoreText",
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            else -> {
                OverallBlock(
                    title = "No VPN detected",
                    summary = "The app did not find any high-level or low-level VPN indicators.",
                    explanation = "Neither official Android network APIs nor interface enumeration produced a VPN-related signal. $scoreText",
                    state = SignalState.NEGATIVE,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "No VPN transport was reported by Android."
                )
            }
        }
    }

    private fun buildApiSignals(
        rawInterfaceName: String?,
        interfaceDetected: Boolean,
        transportInfoSummary: String?,
        transportInfoDetected: Boolean,
        allDnsServers: List<String>,
        internalDnsServers: List<String>,
        contextualInternalDnsServers: List<String>,
        privateDnsActive: Boolean,
        privateDnsServerName: String?,
        activeNetworkNotVpn: Boolean?,
        preferredNetworkNotVpn: Boolean?,
        activeVpn: Boolean,
        anyVpn: Boolean
    ): List<SignalItem> {
        val interfaceTransportDetected = interfaceDetected || transportInfoDetected
        val interfaceState = when {
            interfaceTransportDetected && activeVpn -> SignalState.POSITIVE
            interfaceTransportDetected && anyVpn -> SignalState.SEMI
            interfaceTransportDetected -> SignalState.WARNING
            else -> SignalState.NEGATIVE
        }

        val dnsPolicyDetected =
            internalDnsServers.isNotEmpty() || activeNetworkNotVpn == false || preferredNetworkNotVpn == false
        val dnsState = when {
            internalDnsServers.isNotEmpty() && (activeVpn || anyVpn) -> SignalState.POSITIVE
            dnsPolicyDetected -> SignalState.WARNING
            privateDnsActive -> SignalState.NEUTRAL
            else -> SignalState.NEGATIVE
        }

        val interfaceHint = when {
            interfaceTransportDetected && activeVpn ->
                "Interface naming or transport metadata aligns with an active VPN reported by Android."
            interfaceTransportDetected && anyVpn ->
                "Interface naming or transport metadata aligns with a VPN that exists somewhere in the system."
            interfaceTransportDetected ->
                "Interface naming or transport metadata looks VPN-like, but Android does not currently mark the active path as VPN."
            rawInterfaceName != null ->
                "Android returned interface '$rawInterfaceName' and no VPN-like transport metadata was exposed."
            else ->
                "Android returned no interface or transport metadata for this network."
        }

        val dnsHint = when {
            internalDnsServers.isNotEmpty() && (activeVpn || anyVpn) ->
                "DNS points at internal/private ranges and matches the VPN-related network state."
            internalDnsServers.isNotEmpty() ->
                "DNS points at internal/private ranges often used by VPN clients, but Android did not expose TRANSPORT_VPN."
            contextualInternalDnsServers.isNotEmpty() ->
                "Carrier/private DNS was observed on a cellular interface and is shown as context only, not as a VPN signal."
            activeNetworkNotVpn == false || preferredNetworkNotVpn == false ->
                "At least one inspected network is missing NET_CAPABILITY_NOT_VPN, which is unusual outside VPN-managed paths."
            privateDnsActive ->
                "Private DNS is enabled. This is informational on its own, but useful when correlating DNS leak behavior."
            else ->
                "No suspicious DNS range or NOT_VPN capability anomaly was exposed here."
        }

        val interfaceValue = listOfNotNull(
            rawInterfaceName?.let { "iface=$it" },
            transportInfoSummary?.let { "transport=$it" }
        ).ifEmpty { listOf("none") }.joinToString(" | ")

        val dnsValue = buildList {
            if (internalDnsServers.isNotEmpty()) {
                add("internal=${internalDnsServers.joinToString(", ")}")
            } else if (contextualInternalDnsServers.isNotEmpty()) {
                add("cellular_private_dns=${contextualInternalDnsServers.joinToString(", ")} (not treated as VPN)")
            } else if (allDnsServers.isNotEmpty()) {
                add("dns=${allDnsServers.joinToString(", ")}")
            }
            if (activeNetworkNotVpn != null) add("active_NOT_VPN=$activeNetworkNotVpn")
            if (preferredNetworkNotVpn != null) add("preferred_NOT_VPN=$preferredNetworkNotVpn")
            if (privateDnsActive) {
                add("private_dns=${privateDnsServerName ?: "active"}")
            }
        }.ifEmpty { listOf("none") }.joinToString(" | ")

        return listOf(
            SignalItem(
                title = "Interface / transport",
                source = "LinkProperties + NetworkCapabilities",
                value = interfaceValue,
                state = interfaceState,
                hint = interfaceHint
            ),
            SignalItem(
                title = "DNS / policy",
                source = "LinkProperties + NetworkCapabilities",
                value = dnsValue,
                state = dnsState,
                hint = dnsHint
            )
        )
    }

    private data class OverallBlock(
        val title: String,
        val summary: String,
        val explanation: String,
        val state: SignalState,
        val transportState: SignalState,
        val transportText: String,
        val transportSubtitle: String
    )

    private fun DetectionConfidence.label(): String {
        return when (this) {
            DetectionConfidence.CONFIRMED -> "confirmed"
            DetectionConfidence.LIKELY -> "likely"
            DetectionConfidence.WEAK_SIGNAL -> "weak signal"
            DetectionConfidence.NO_EVIDENCE -> "no evidence"
        }
    }
}
