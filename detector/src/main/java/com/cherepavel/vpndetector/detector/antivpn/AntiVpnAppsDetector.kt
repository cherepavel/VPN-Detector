package com.cherepavel.vpndetector.detector.antivpn

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.cherepavel.vpndetector.model.AntiVpnAppHit
import com.cherepavel.vpndetector.model.AntiVpnConfidence
import com.cherepavel.vpndetector.model.AntiVpnDetectionResult
import com.cherepavel.vpndetector.model.AntiVpnScanMode
import com.cherepavel.vpndetector.model.AntiVpnSeverity
import com.cherepavel.vpndetector.model.KnownAntiVpnApp

/**
 * Finds installed applications that look like they contain
 * anti-VPN-detection logic, so the user can be warned to disable their
 * VPN before using them.
 *
 * Two tiers:
 *
 *  1. **Curated list** ([KnownAntiVpnRepository]) — apps that are
 *     publicly known/suspected to block on VPN. Any installed package
 *     that matches an entry is reported with [AntiVpnConfidence.CONFIRMED].
 *  2. **Static DEX scan** ([DexSignatureScanner]) — in
 *     [AntiVpnScanMode.DEEP] mode only, installed non-system apps are
 *     also scanned for byte-level signatures. Hits are reported as
 *     `LIKELY` or `POSSIBLE` depending on score.
 *
 * This detector makes no network calls, requests no new permissions, and
 * only reads files the OS already lets the caller read
 * (`ApplicationInfo.sourceDir`).
 */
class AntiVpnAppsDetector(
    private val context: Context,
    private val scanner: DexSignatureScanner = DexSignatureScanner(),
    private val repository: (Context) -> List<KnownAntiVpnApp> = KnownAntiVpnRepository::get
) {

    companion object {
        /** Do not attempt to deep-scan more than this many apps per run. */
        internal const val MAX_DEEP_SCAN_APPS: Int = 40
    }

    fun detect(mode: AntiVpnScanMode = AntiVpnScanMode.FAST): AntiVpnDetectionResult {
        val known = repository(context)
        val hits = linkedMapOf<String, AntiVpnAppHit>()
        val errors = mutableMapOf<String, String>()

        // Tier 1: curated list matches. Fast, deterministic, no IO.
        for (app in known) {
            val info = getApplicationInfoOrNull(app.packageName, onError = { err ->
                if (err != PackageManager.NameNotFoundException::class.java.simpleName) {
                    errors[app.packageName] = err
                }
            }) ?: continue

            hits[app.packageName] = AntiVpnAppHit(
                packageName = app.packageName,
                label = app.label,
                category = app.category,
                severity = app.severity,
                confidence = AntiVpnConfidence.CONFIRMED,
                signals = listOf("Curated list: ${app.category}"),
                score = 0,
                evidence = app.evidence.ifBlank { null }
            )
            // We intentionally do not also deep-scan CONFIRMED apps — the
            // curated entry is more reliable than any heuristic match.
            info.hashCode() // keep `info` usage explicit for readability
        }

        if (mode == AntiVpnScanMode.FAST) {
            return AntiVpnDetectionResult(
                hits = hits.values.toList(),
                scanMode = AntiVpnScanMode.FAST,
                scannedPackageCount = 0,
                errors = errors
            )
        }

        // Tier 2: deep scan of non-curated, user-installed, non-system apps.
        val candidates = listCandidateApps()
            .filter { it.packageName !in hits.keys }
            .take(MAX_DEEP_SCAN_APPS)

        var scannedCount = 0
        for (info in candidates) {
            val path = info.sourceDir ?: continue
            scannedCount++

            val result = try {
                scanner.scanApk(path)
            } catch (t: Throwable) {
                errors[info.packageName] = "scan: ${t.javaClass.simpleName}: ${t.message ?: ""}"
                continue
            }

            if (result.score < AntiVpnSignatures.SCORE_POSSIBLE) continue

            val confidence = if (result.score >= AntiVpnSignatures.SCORE_LIKELY) {
                AntiVpnConfidence.LIKELY
            } else {
                AntiVpnConfidence.POSSIBLE
            }

            val label = loadLabel(info)
            hits[info.packageName] = AntiVpnAppHit(
                packageName = info.packageName,
                label = label,
                category = "unknown",
                severity = confidenceToSeverity(confidence),
                confidence = confidence,
                signals = result.matches.map { it.label },
                score = result.score,
                evidence = null
            )
        }

        return AntiVpnDetectionResult(
            hits = hits.values.toList(),
            scanMode = AntiVpnScanMode.DEEP,
            scannedPackageCount = scannedCount,
            errors = errors
        )
    }

    private fun listCandidateApps(): List<ApplicationInfo> {
        val pm = context.packageManager
        val all = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledApplications(0)
            }
        } catch (_: Throwable) {
            emptyList()
        }

        return all.filter { info ->
            // Skip system apps (including updated system apps) — those are
            // not user-installed and rarely do VPN detection as part of
            // the relevant threat model, while contributing huge scan
            // volumes.
            (info.flags and ApplicationInfo.FLAG_SYSTEM) == 0 &&
                    info.packageName != context.packageName
        }
    }

    private fun getApplicationInfoOrNull(
        packageName: String,
        onError: (String) -> Unit
    ): ApplicationInfo? {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getApplicationInfo(packageName, 0)
            }
        } catch (_: PackageManager.NameNotFoundException) {
            onError(PackageManager.NameNotFoundException::class.java.simpleName)
            null
        } catch (e: Throwable) {
            onError("${e.javaClass.simpleName}: ${e.message ?: ""}")
            null
        }
    }

    private fun loadLabel(info: ApplicationInfo): String {
        return try {
            context.packageManager.getApplicationLabel(info).toString()
        } catch (_: Throwable) {
            info.packageName
        }
    }

    private fun confidenceToSeverity(confidence: AntiVpnConfidence): AntiVpnSeverity {
        // Heuristic hits don't have a real severity — we map by confidence
        // so the UI still has a color to show.
        return when (confidence) {
            AntiVpnConfidence.CONFIRMED -> AntiVpnSeverity.HIGH
            AntiVpnConfidence.LIKELY -> AntiVpnSeverity.MEDIUM
            AntiVpnConfidence.POSSIBLE -> AntiVpnSeverity.LOW
        }
    }
}
