package com.cherepavel.vpndetector.ui

import android.content.Context
import com.cherepavel.vpndetector.R
import com.cherepavel.vpndetector.detector.TunnelNameMatcher
import com.cherepavel.vpndetector.model.DetectionConfidence
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.model.DetectionStatus

object ReportFormatter {

    fun build(context: Context, snapshot: DetectionSnapshot): DetectionReport {
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
            context = context,
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
            context = context,
            rawInterfaceName = snapshot.rawInterfaceName,
            interfaceDetected = interfaceDetected,
            transportInfoSummary = snapshot.transportInfoSummary,
            transportInfoDetected = transportInfoDetected,
            activeVpn = activeVpn,
            anyVpn = anyVpn
        )

        val nativeSignal = SignalItem(
            title = context.getString(R.string.signal_title_tunnel_like_interfaces),
            source = context.getString(R.string.signal_source_native),
            value = snapshot.nativeTunnelNames.ifEmpty {
                listOf(context.getString(R.string.report_value_none))
            }.joinToString(", "),
            state = if (nativeDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (nativeDetected) {
                context.getString(R.string.signal_hint_native_found)
            } else {
                context.getString(R.string.signal_hint_native_missing)
            }
        )

        val javaSignal = SignalItem(
            title = context.getString(R.string.signal_title_tunnel_like_interfaces),
            source = context.getString(R.string.signal_source_java),
            value = snapshot.javaTunnelNames.ifEmpty {
                listOf(context.getString(R.string.report_value_none))
            }.joinToString(", "),
            state = if (javaDetected) SignalState.WARNING else SignalState.NEGATIVE,
            hint = if (javaDetected) {
                context.getString(R.string.signal_hint_java_found)
            } else {
                context.getString(R.string.signal_hint_java_missing)
            }
        )

        val nativeDetailsText = buildString {
            if (snapshot.nativeError != null) {
                appendLine(
                    context.getString(
                        R.string.native_error_format,
                        snapshot.nativeError
                    )
                )
                appendLine()
            }
            if (snapshot.nativeDetails.isNotEmpty()) {
                append(snapshot.nativeDetails.joinToString(separator = "\n\n"))
            } else if (snapshot.nativeError == null) {
                append(context.getString(R.string.native_details_empty))
            }
        }.trim()

        val extraSections = buildList {
            if (snapshot.tunTypeInterfaces.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_tun_interfaces),
                        body = snapshot.tunTypeInterfaces.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.lowMtuInterfaces.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_low_mtu_interfaces),
                        body = snapshot.lowMtuInterfaces.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.vpnRoutes.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_vpn_routes),
                        body = snapshot.vpnRoutes.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.vpnDnsServers.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_vpn_dns_servers),
                        body = snapshot.vpnDnsServers.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.allDnsServers.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_dns_all),
                        body = snapshot.allDnsServers.joinToString("\n"),
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.internalDnsServers.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_dns_internal),
                        body = snapshot.internalDnsServers.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.contextualInternalDnsServers.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_dns_contextual),
                        body = snapshot.contextualInternalDnsServers.joinToString("\n"),
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.privateDnsActive || snapshot.privateDnsServerName != null) {
                val privateDnsState = if (snapshot.privateDnsActive) {
                    context.getString(R.string.private_dns_active)
                } else {
                    context.getString(R.string.private_dns_inactive)
                }

                val privateDnsBody = snapshot.privateDnsServerName?.let {
                    context.getString(R.string.private_dns_with_host, privateDnsState, it)
                } ?: privateDnsState

                add(
                    DetailSection(
                        title = context.getString(R.string.section_private_dns),
                        body = privateDnsBody,
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.activeNetworkNotVpn != null || snapshot.preferredNetworkNotVpn != null) {
                val activeText = snapshot.activeNetworkNotVpn?.toString()
                    ?: context.getString(R.string.report_value_unknown)
                val preferredText = snapshot.preferredNetworkNotVpn?.toString()
                    ?: context.getString(R.string.report_value_unknown)

                add(
                    DetailSection(
                        title = context.getString(R.string.section_not_vpn),
                        body = context.getString(
                            R.string.not_vpn_body,
                            activeText,
                            preferredText
                        ),
                        state = if (
                            snapshot.activeNetworkNotVpn == false ||
                            snapshot.preferredNetworkNotVpn == false
                        ) {
                            SignalState.WARNING
                        } else {
                            SignalState.NEUTRAL
                        }
                    )
                )
            }

            snapshot.vpnBandwidthSummary?.let {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_vpn_bandwidth),
                        body = it,
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.kernelRoutes.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_kernel_routes_v4),
                        body = snapshot.kernelRoutes.joinToString("\n"),
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.kernelIpv6Routes.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_kernel_routes_v6),
                        body = snapshot.kernelIpv6Routes.joinToString("\n"),
                        state = SignalState.NEUTRAL
                    )
                )
            }

            if (snapshot.vpnPermissionGranted) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_vpn_permission),
                        body = context.getString(R.string.vpn_permission_body),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.lockdownLikely) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_lockdown),
                        body = context.getString(R.string.lockdown_body),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.knownVpnDnsMatches.isNotEmpty()) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_known_vpn_dns),
                        body = snapshot.knownVpnDnsMatches.joinToString("\n"),
                        state = SignalState.WARNING
                    )
                )
            }

            if (snapshot.workProfileCount > 1 || snapshot.isManagedProfile) {
                add(
                    DetailSection(
                        title = context.getString(R.string.section_work_profile),
                        body = buildString {
                            if (snapshot.isManagedProfile) {
                                appendLine(context.getString(R.string.managed_profile_body))
                            }
                            if (snapshot.workProfileCount > 1) {
                                append(
                                    context.getString(
                                        R.string.work_profile_count_body,
                                        snapshot.workProfileCount
                                    )
                                )
                            }
                        }.trim(),
                        state = SignalState.NEUTRAL
                    )
                )
            }
        }

        val appsText = buildString {
            if (snapshot.installedVpnApps.isEmpty() && snapshot.unknownDynamicApps.isEmpty()) {
                append(context.getString(R.string.apps_none_detected))
            } else {
                snapshot.installedVpnApps.forEach { appendLine("• $it") }
                if (snapshot.unknownDynamicApps.isNotEmpty()) {
                    if (snapshot.installedVpnApps.isNotEmpty()) appendLine()
                    appendLine(context.getString(R.string.apps_detected_via_vpn_service))
                    snapshot.unknownDynamicApps.forEach { appendLine("• $it") }
                }
            }
            if (snapshot.trackedAppsErrors.isNotEmpty()) {
                if (snapshot.installedVpnApps.isNotEmpty() || snapshot.unknownDynamicApps.isNotEmpty()) {
                    appendLine()
                }
                appendLine(context.getString(R.string.apps_check_errors))
                snapshot.trackedAppsErrors.forEach { (pkg, err) ->
                    appendLine("• $pkg: $err")
                }
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
            transportAnyValue = if (anyVpn) {
                context.getString(R.string.report_value_detected)
            } else {
                context.getString(R.string.report_value_not_detected)
            },
            transportActiveValue = if (activeVpn) {
                context.getString(R.string.report_value_detected)
            } else {
                context.getString(R.string.report_value_not_detected)
            },
            transportAnyDetected = anyVpn,
            transportActiveDetected = activeVpn,

            apiSignals = apiSignals,
            nativeSignal = nativeSignal,
            nativeDetails = nativeDetailsText,
            extraSections = extraSections,
            javaSignal = javaSignal,
            knownAppsText = appsText
        )
    }

    private fun buildOverallBlock(
        context: Context,
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
        val confidenceText = when (snapshot.assessment.confidence) {
            DetectionConfidence.CONFIRMED -> context.getString(R.string.report_confidence_confirmed)
            DetectionConfidence.LIKELY -> context.getString(R.string.report_confidence_likely)
            DetectionConfidence.WEAK_SIGNAL -> context.getString(R.string.report_confidence_weak_signal)
            DetectionConfidence.NO_EVIDENCE -> context.getString(R.string.report_confidence_no_evidence)
        }

        val scoreText = context.getString(
            R.string.report_confidence_format,
            confidenceText,
            snapshot.assessment.score
        )

        return when {
            snapshot.assessment.status == DetectionStatus.ACTIVE_VPN || activeVpn -> {
                val lockdown = snapshot.lockdownLikely
                val summary = context.getString(R.string.report_summary_vpn_detected) +
                        if (lockdown) " " + context.getString(R.string.report_summary_lockdown_suffix) else ""

                OverallBlock(
                    title = context.getString(
                        if (lockdown) R.string.report_title_vpn_detected_lockdown
                        else R.string.report_title_vpn_detected
                    ),
                    summary = summary,
                    explanation = context.getString(R.string.report_explanation_vpn_detected) +
                            " " + scoreText,
                    state = SignalState.POSITIVE,
                    transportState = SignalState.POSITIVE,
                    transportText = context.getString(R.string.report_transport_text_vpn_detected),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_vpn_detected)
                )
            }

            snapshot.assessment.status == DetectionStatus.SPLIT_TUNNEL || anyVpn -> {
                OverallBlock(
                    title = context.getString(R.string.report_title_split_tunnel),
                    summary = context.getString(R.string.report_summary_split_tunnel),
                    explanation = context.getString(R.string.report_explanation_split_tunnel) +
                            " " + scoreText,
                    state = SignalState.SEMI,
                    transportState = SignalState.SEMI,
                    transportText = context.getString(R.string.report_transport_text_split_tunnel),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_split_tunnel)
                )
            }

            interfaceDetected || transportInfoDetected || dnsDetected || policyDetected -> {
                OverallBlock(
                    title = context.getString(R.string.report_title_api_signal),
                    summary = context.getString(R.string.report_summary_api_signal),
                    explanation = context.getString(R.string.report_explanation_api_signal) +
                            " " + scoreText,
                    state = SignalState.WARNING,
                    transportState = SignalState.WARNING,
                    transportText = context.getString(R.string.report_transport_text_api_signal),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_api_signal)
                )
            }

            nativeDetected || javaDetected -> {
                OverallBlock(
                    title = context.getString(R.string.report_title_low_level),
                    summary = context.getString(R.string.report_summary_low_level),
                    explanation = context.getString(R.string.report_explanation_low_level) +
                            " " + scoreText,
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = context.getString(R.string.report_transport_text_not_detected),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_not_on_active_path)
                )
            }

            snapshot.assessment.status == DetectionStatus.APPS_PRESENT || appsDetected -> {
                OverallBlock(
                    title = context.getString(R.string.report_title_apps_present),
                    summary = context.getString(R.string.report_summary_apps_present),
                    explanation = context.getString(R.string.report_explanation_apps_present) +
                            " " + scoreText,
                    state = SignalState.WARNING,
                    transportState = SignalState.NEGATIVE,
                    transportText = context.getString(R.string.report_transport_text_not_detected),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_not_on_active_path)
                )
            }

            else -> {
                OverallBlock(
                    title = context.getString(R.string.report_title_no_vpn),
                    summary = context.getString(R.string.report_summary_no_vpn),
                    explanation = context.getString(R.string.report_explanation_no_vpn) +
                            " " + scoreText,
                    state = SignalState.NEGATIVE,
                    transportState = SignalState.NEGATIVE,
                    transportText = context.getString(R.string.report_transport_text_not_detected),
                    transportSubtitle = context.getString(R.string.report_transport_subtitle_not_detected)
                )
            }
        }
    }

    private fun buildApiSignals(
        context: Context,
        rawInterfaceName: String?,
        interfaceDetected: Boolean,
        transportInfoSummary: String?,
        transportInfoDetected: Boolean,
        activeVpn: Boolean,
        anyVpn: Boolean
    ): List<SignalItem> {
        val interfaceState = when {
            interfaceDetected && (activeVpn || anyVpn) -> SignalState.POSITIVE
            interfaceDetected -> SignalState.WARNING
            else -> SignalState.NEGATIVE
        }

        val transportInfoState = when {
            transportInfoDetected && (activeVpn || anyVpn) -> SignalState.POSITIVE
            transportInfoDetected -> SignalState.WARNING
            else -> SignalState.NEGATIVE
        }

        val interfaceHint = when {
            interfaceDetected && activeVpn ->
                context.getString(R.string.signal_hint_interface_active)
            interfaceDetected && anyVpn ->
                context.getString(R.string.signal_hint_interface_any)
            interfaceDetected ->
                context.getString(R.string.signal_hint_interface_only)
            rawInterfaceName != null ->
                context.getString(R.string.signal_hint_interface_normal)
            else ->
                context.getString(R.string.signal_hint_interface_missing)
        }

        val transportInfoHint = when {
            transportInfoDetected && activeVpn ->
                context.getString(R.string.signal_hint_transport_active)
            transportInfoDetected && anyVpn ->
                context.getString(R.string.signal_hint_transport_any)
            transportInfoDetected ->
                context.getString(R.string.signal_hint_transport_only)
            else ->
                context.getString(R.string.signal_hint_transport_missing)
        }

        return listOf(
            SignalItem(
                title = context.getString(R.string.signal_title_interface_name),
                source = context.getString(R.string.signal_source_interface_name),
                value = rawInterfaceName?.let(::softWrapToken)
                    ?: context.getString(R.string.report_value_none),
                state = interfaceState,
                hint = interfaceHint
            ),
            SignalItem(
                title = context.getString(R.string.signal_title_transport_info),
                source = context.getString(R.string.signal_source_transport_info),
                value = formatCompactTransportInfo(transportInfoSummary)
                    ?: context.getString(R.string.report_value_none),
                state = transportInfoState,
                hint = transportInfoHint
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
            else -> softWrapToken(normalized)
        }
    }

    private fun softWrapToken(value: String): String {
        return value
            .replace("(", "(\u200B")
            .replace(")", "\u200B)")
            .replace("/", "/\u200B")
            .replace("-", "-\u200B")
            .replace("_", "_\u200B")
            .replace(",", ",\u200B")
    }
}
