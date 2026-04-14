package com.cherepavel.vpndetector.detector.antivpn

import android.content.Context
import com.cherepavel.vpndetector.model.AntiVpnSeverity
import com.cherepavel.vpndetector.model.KnownAntiVpnApp
import org.json.JSONArray

/**
 * Loads the curated list of apps known/suspected to perform anti-VPN checks
 * from `assets/anti_vpn_apps.json`.
 *
 * Mirrors [com.cherepavel.vpndetector.detector.TrackedAppsRepository] — the
 * same pattern of in-memory caching + lazy load from the APK asset stream.
 *
 * The list ships with the APK and is only updated via new app releases; the
 * detector itself never fetches anything over the network.
 */
object KnownAntiVpnRepository {

    private const val FILE_NAME = "anti_vpn_apps.json"

    @Volatile
    private var cached: List<KnownAntiVpnApp>? = null

    fun get(context: Context): List<KnownAntiVpnApp> {
        cached?.let { return it }

        return try {
            val json = context.applicationContext.assets
                .open(FILE_NAME)
                .bufferedReader()
                .use { it.readText() }

            parse(json).also { cached = it }
        } catch (_: Exception) {
            emptyList()
        }
    }

    internal fun parse(json: String): List<KnownAntiVpnApp> {
        val array = JSONArray(json)
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            KnownAntiVpnApp(
                packageName = obj.getString("packageName"),
                label = obj.getString("label"),
                category = obj.optString("category", "unknown"),
                severity = parseSeverity(obj.optString("severity", "medium")),
                evidence = obj.optString("evidence", "")
            )
        }
    }

    private fun parseSeverity(raw: String): AntiVpnSeverity {
        return when (raw.lowercase()) {
            "high" -> AntiVpnSeverity.HIGH
            "low" -> AntiVpnSeverity.LOW
            else -> AntiVpnSeverity.MEDIUM
        }
    }
}
