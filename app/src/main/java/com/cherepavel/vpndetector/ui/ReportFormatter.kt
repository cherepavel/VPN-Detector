package com.cherepavel.vpndetector.ui

import com.cherepavel.vpndetector.detector.TunnelNameMatcher

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

    val apiSignals: List<SignalItem>,
    val nativeSignal: SignalItem,
    val nativeDetails: String,
    val javaSignal: SignalItem,
    val knownAppsText: String
)

object ReportFormatter {

    data class RawInput(
        val hasTransportVpnAny: Boolean,
        val hasTransportVpnActive: Boolean,
        /** Raw value from LinkProperties.getInterfaceName(), always unfiltered. */
        val rawInterfaceName: String?,
        val transportInfoSummary: String?,
        val nativeTunnelNames: List<String>,
        val nativeDetails: List<String>,
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

    fun build(input: RawInput): DetectionReport {
        val anyVpn = input.hasTransportVpnAny
        val activeVpn = input.hasTransportVpnActive

        val interfaceDetected = TunnelNameMatcher.looksLikeTunnelName(input.rawInterfaceName)
        val transportInfoDetected = !input.transportInfoSummary.isNullOrBlank()
        val dnsDetected = input.internalDnsServers.isNotEmpty()
        val policyDetected =
            input.activeNetworkNotVpn == false || input.preferredNetworkNotVpn == false
        val nativeDetected = input.nativeTunnelNames.isNotEmpty()
        val javaDetected = input.javaTunnelNames.isNotEmpty()
        val appsDetected = input.installedVpnApps.isNotEmpty()

        val overall = buildOverallBlock(
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
            rawInterfaceName = input.rawInterfaceName,
            interfaceDetected = interfaceDetected,
            transportInfoSummary = input.transportInfoSummary,
            transportInfoDetected = transportInfoDetected,
            allDnsServers = input.allDnsServers,
            internalDnsServers = input.internalDnsServers,
            contextualInternalDnsServers = input.contextualInternalDnsServers,
            privateDnsActive = input.privateDnsActive,
            privateDnsServerName = input.privateDnsServerName,
            activeNetworkNotVpn = input.activeNetworkNotVpn,
            preferredNetworkNotVpn = input.preferredNetworkNotVpn,
            activeVpn = activeVpn,
            anyVpn = anyVpn
        )

        val nativeSignal = SignalItem(
            title = "Tunnel-like interfaces",
            source = "Native getifaddrs() enumeration",
            value = input.nativeTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
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
            value = input.javaTunnelNames.ifEmpty { listOf("none") }.joinToString(", "),
            state = if (javaDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (javaDetected) {
                "Java network enumeration found interface names that look like VPN or tunnel interfaces."
            } else {
                "Java network enumeration did not find any tunnel-like interface names."
            }
        )

        val nativeDetailsText = buildString {
            if (input.nativeError != null) {
                appendLine("Native detector error: ${input.nativeError}")
                appendLine()
            }
            if (input.nativeDetails.isNotEmpty()) {
                append(input.nativeDetails.joinToString(separator = "\n\n"))
            } else if (input.nativeError == null) {
                append("No interfaces were returned by the native detector.")
            }
            if (input.tunTypeInterfaces.isNotEmpty()) {
                append("\n\n--- TUN interfaces (type=65534) ---\n")
                append(input.tunTypeInterfaces.joinToString(", "))
            }
            if (input.lowMtuInterfaces.isNotEmpty()) {
                append("\n\n--- Low-MTU interfaces (<1500) ---\n")
                append(input.lowMtuInterfaces.joinToString("\n"))
            }
            if (input.vpnRoutes.isNotEmpty()) {
                append("\n\n--- VPN network routes ---\n")
                append(input.vpnRoutes.joinToString("\n"))
            }
            if (input.vpnDnsServers.isNotEmpty()) {
                append("\n\n--- VPN DNS servers ---\n")
                append(input.vpnDnsServers.joinToString(", "))
            }
            if (input.allDnsServers.isNotEmpty()) {
                append("\n\n--- DNS servers across visible networks ---\n")
                append(input.allDnsServers.joinToString("\n"))
            }
            if (input.internalDnsServers.isNotEmpty()) {
                append("\n\n--- Internal/private-range DNS servers ---\n")
                append(input.internalDnsServers.joinToString("\n"))
            }
            if (input.contextualInternalDnsServers.isNotEmpty()) {
                append("\n\n--- Cellular private DNS observed (not treated as VPN) ---\n")
                append(input.contextualInternalDnsServers.joinToString("\n"))
            }
            if (input.privateDnsActive || input.privateDnsServerName != null) {
                append("\n\n--- Private DNS ---\n")
                append(
                    buildString {
                        append(if (input.privateDnsActive) "active" else "inactive")
                        input.privateDnsServerName?.let { append(" ($it)") }
                    }
                )
            }
            if (input.activeNetworkNotVpn != null || input.preferredNetworkNotVpn != null) {
                append("\n\n--- NET_CAPABILITY_NOT_VPN ---\n")
                append("active=")
                append(input.activeNetworkNotVpn?.toString() ?: "unknown")
                append(", preferred=")
                append(input.preferredNetworkNotVpn?.toString() ?: "unknown")
            }
            if (input.underlyingNetworksSummary != null) {
                append("\n\n--- Underlying physical networks ---\n")
                append(input.underlyingNetworksSummary)
            }
            if (input.vpnBandwidthSummary != null) {
                append("\n\n--- VPN bandwidth ---\n")
                append(input.vpnBandwidthSummary)
            }
            if (input.kernelRoutes.isNotEmpty()) {
                append("\n\n--- Kernel route table (/proc/net/route) ---\n")
                append(input.kernelRoutes.joinToString("\n"))
            }
            if (input.kernelIpv6Routes.isNotEmpty()) {
                append("\n\n--- Kernel route table (/proc/net/ipv6_route) ---\n")
                append(input.kernelIpv6Routes.joinToString("\n"))
            }
            if (input.proxyInfo != null) {
                append("\n\n--- Proxy detection ---\n")
                append(input.proxyInfo)
            }
            if (input.vpnPermissionGranted) {
                append("\n\n--- VPN permission ---\n")
                append("This app holds Android VPN permission (anomalous for a detector).")
            }
        }

        val dynamicUnknown = input.dynamicVpnApps.filter { pkg ->
            input.installedVpnApps.none { it.contains(pkg) }
        }
        val appsText = buildString {
            if (input.installedVpnApps.isEmpty() && dynamicUnknown.isEmpty()) {
                append("No VPN-related apps detected.")
            } else {
                input.installedVpnApps.forEach { appendLine("• $it") }
                if (dynamicUnknown.isNotEmpty()) {
                    if (input.installedVpnApps.isNotEmpty()) appendLine()
                    appendLine("Detected via VpnService query:")
                    dynamicUnknown.forEach { appendLine("• $it") }
                }
            }
            if (input.trackedAppsErrors.isNotEmpty()) {
                if (input.installedVpnApps.isNotEmpty() || dynamicUnknown.isNotEmpty()) appendLine()
                appendLine("Check errors (package manager returned unexpected error):")
                input.trackedAppsErrors.forEach { (pkg, err) -> appendLine("• $pkg: $err") }
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

            apiSignals = apiSignals,
            nativeSignal = nativeSignal,
            nativeDetails = nativeDetailsText,
            javaSignal = javaSignal,
            knownAppsText = appsText
        )
    }

    private fun buildOverallBlock(
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
        return when {
            activeVpn -> {
                OverallBlock(
                    title = "VPN detected",
                    summary = "The active network is explicitly marked as VPN by Android.",
                    explanation = "This is the strongest signal in the app: Android reports TRANSPORT_VPN on the network currently in use.",
                    state = SignalState.POSITIVE,
                    transportState = SignalState.POSITIVE,
                    transportText = "VPN DETECTED",
                    transportSubtitle = "TRANSPORT_VPN is present on the active network."
                )
            }

            anyVpn -> {
                OverallBlock(
                    title = "VPN present outside active path",
                    summary = "Android sees a VPN network in the system, but not on the current active network.",
                    explanation = "This often matches bypass or split-tunnel behavior: a VPN exists, but current traffic may not be fully routed through it.",
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
                    explanation = "This is weaker than a direct VPN transport flag, but interface, DNS, or capability signals still suggest VPN-related state in the visible network stack.",
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
                    explanation = "This usually means only low-level interface heuristics fired. It is useful as an additional hint, but weaker than official Android VPN signals.",
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = "NOT DETECTED",
                    transportSubtitle = "Android did not report VPN transport on the active path."
                )
            }

            appsDetected -> {
                OverallBlock(
                    title = "Detected VPN apps",
                    summary = "No active VPN network signal was found, but known VPN-related apps are installed on the device.",
                    explanation = "Installed VPN apps do not prove that a VPN is currently active, but they are still a relevant contextual signal.",
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
                    explanation = "Neither official Android network APIs nor interface enumeration produced a VPN-related signal.",
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
}
