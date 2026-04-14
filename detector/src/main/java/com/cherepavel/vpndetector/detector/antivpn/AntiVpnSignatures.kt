package com.cherepavel.vpndetector.detector.antivpn

/**
 * Static byte-level signatures used by [DexSignatureScanner] to flag
 * installed applications whose compiled code looks like it performs
 * VPN-presence checks.
 *
 * Rationale
 * ---------
 * DEX files keep **all references to framework classes and methods as
 * plain UTF-8 strings** in their string table (R8/ProGuard cannot rename
 * `Landroid/net/ConnectivityManager;` — that name is fixed by the Android
 * runtime). String literals inside user code (`"tun0"`, `"wg0"`, SDK class
 * prefixes) also typically survive obfuscation unmodified.
 *
 * So a byte-level search for a curated set of short markers gives a cheap
 * and reasonably accurate first pass, without linking against dexlib2 or
 * any heavyweight analyzer. The approach has false positives — any app
 * that legitimately reads `ConnectivityManager` will match the weak
 * signals — so we scale responses by total weight and only flag when
 * several signals fire together.
 *
 * This file is the single source of truth for the scoring heuristic and
 * is intentionally short and readable so it can be reviewed and tuned
 * against real APKs.
 */
object AntiVpnSignatures {

    /**
     * A signature the scanner looks for as a raw UTF-8 substring of a
     * classes*.dex or lib/*.so file.
     *
     * @param label human-readable name shown in the detection report
     * @param pattern bytes to search for (ASCII, case-sensitive)
     * @param weight score added to the target app's total when present.
     *   Designed so that two strong signals (≥ 10) push the app into
     *   `LIKELY`, a single strong + several weak hits reach `POSSIBLE`,
     *   and only weak noise stays under both thresholds.
     */
    data class Signature(
        val label: String,
        val pattern: ByteArray,
        val weight: Int
    ) {
        /** Stable identity for deduplication of human-readable hit labels. */
        override fun equals(other: Any?): Boolean =
            other is Signature && other.label == label

        override fun hashCode(): Int = label.hashCode()
    }

    /** Threshold at or above which the scanner emits a `LIKELY` hit. */
    const val SCORE_LIKELY: Int = 10

    /** Lower bound for `POSSIBLE` (below this, the scan emits nothing). */
    const val SCORE_POSSIBLE: Int = 5

    private fun sig(label: String, needle: String, weight: Int): Signature =
        Signature(label, needle.toByteArray(Charsets.UTF_8), weight)

    /**
     * Strong signals — the presence of any single one is a significant
     * hint that the app specifically reasons about VPN state.
     */
    private val strong: List<Signature> = listOf(
        // Explicit "is the connection NOT over a VPN?" check. This is the
        // textbook anti-VPN API call and the single most discriminating
        // marker we can find without decompiling.
        sig("NET_CAPABILITY_NOT_VPN reference", "NET_CAPABILITY_NOT_VPN", 8),

        // TRANSPORT_VPN constant - used with hasTransport(...) for both
        // "require VPN" and "reject VPN" checks. Less unique than
        // NOT_VPN but still a strong tell.
        sig("TRANSPORT_VPN reference", "TRANSPORT_VPN", 6),

        // Typical manually-hardcoded tunnel interface name literals.
        // The Android SDK does not expose these as constants, so an app
        // that ships them in its DEX is almost always doing manual
        // `NetworkInterface` enumeration for anti-VPN purposes.
        sig("tun0 literal", "tun0", 5),
        sig("wg0 literal", "wg0", 5),
        sig("ppp0 literal", "ppp0", 4)
    )

    /**
     * Medium signals — individually harmless (every chat app touches
     * ConnectivityManager), but weighted so that several of them
     * together with at least one strong hit pushes into LIKELY.
     */
    private val medium: List<Signature> = listOf(
        sig("hasTransport call", "hasTransport", 2),
        sig("getAllNetworks call", "getAllNetworks", 2),
        sig("getNetworkCapabilities call", "getNetworkCapabilities", 2),
        sig("NetworkInterface.getNetworkInterfaces", "getNetworkInterfaces", 2),
        sig("isUp call", "isUp", 1),

        // Known anti-fraud / device-fingerprinting SDK package prefixes.
        // Presence does not prove anti-VPN behaviour, but these SDKs are
        // frequently the ones that ship VPN detectors.
        sig("IPQualityScore SDK", "com/ipqualityscore", 3),
        sig("ThreatMetrix SDK", "com/threatmetrix", 3),
        sig("Fingerprint.com SDK", "io/fingerprint", 3),
        sig("Arkose Labs SDK", "com/arkoselabs", 3),
        sig("Incognia SDK", "com/incognia", 3),
        sig("iovation SDK", "com/iovation", 3),
        sig("Sift SDK", "com/sift", 2)
    )

    /**
     * Native-library signals — scanned against `lib/<abi>/*.so` inside
     * the APK. These cover apps that do VPN detection in C/C++ to evade
     * Java-side reverse engineering.
     */
    private val native: List<Signature> = listOf(
        sig("getifaddrs in native lib", "getifaddrs", 4),
        sig("/proc/net/route read", "/proc/net/route", 5),
        sig("/proc/net/ipv6_route read", "/proc/net/ipv6_route", 4),
        sig("tun0 literal in native lib", "tun0", 3)
    )

    /** Signatures applied to DEX bytecode files. */
    val dexSignatures: List<Signature> = strong + medium

    /** Signatures applied to packaged native libraries. */
    val nativeSignatures: List<Signature> = native
}
