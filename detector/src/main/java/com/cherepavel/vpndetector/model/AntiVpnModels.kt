package com.cherepavel.vpndetector.model

/**
 * How confident we are that a given installed app contains anti-VPN logic.
 *
 * - [CONFIRMED] — package is present in the curated `anti_vpn_apps.json` list.
 * - [LIKELY] — strong static-signature match in the APK (e.g. explicit use of
 *   NET_CAPABILITY_NOT_VPN or string literals `tun0`/`wg0`).
 * - [POSSIBLE] — weaker aggregate signal from the DEX scan.
 */
enum class AntiVpnConfidence {
    CONFIRMED,
    LIKELY,
    POSSIBLE
}

enum class AntiVpnSeverity {
    /** App is known/suspected to block functionality when a VPN is detected. */
    HIGH,

    /** App is known/suspected to degrade service (e.g. region lock) when VPN is present. */
    MEDIUM,

    /** App merely detects / warns but keeps working. */
    LOW
}

/**
 * One curated entry in `anti_vpn_apps.json`.
 */
data class KnownAntiVpnApp(
    val packageName: String,
    val label: String,
    val category: String,
    val severity: AntiVpnSeverity,
    val evidence: String
)

/**
 * A detection hit — either from the curated list or from static APK scan.
 */
data class AntiVpnAppHit(
    val packageName: String,
    val label: String,
    val category: String,
    val severity: AntiVpnSeverity,
    val confidence: AntiVpnConfidence,
    /** Human-readable signals that contributed to the hit. */
    val signals: List<String>,
    /** Score from the static scanner (0 for CONFIRMED-only hits). */
    val score: Int,
    /** External source / citation for CONFIRMED entries. */
    val evidence: String?
)

/**
 * Result of running the anti-VPN detector.
 *
 * [scanMode] reflects what was actually executed (fast path vs deep scan);
 * [scannedPackageCount] helps show the user how many apps were evaluated by
 * the static scanner in deep mode.
 */
data class AntiVpnDetectionResult(
    val hits: List<AntiVpnAppHit>,
    val scanMode: AntiVpnScanMode,
    val scannedPackageCount: Int,
    val errors: Map<String, String>
)

enum class AntiVpnScanMode {
    /** Only compare installed packages against the curated JSON list. */
    FAST,

    /** Also run static DEX / native lib signature scan on non-curated apps. */
    DEEP
}
