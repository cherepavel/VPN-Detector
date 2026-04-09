package com.cherepavel.vpndetector.detector

import android.content.Context
import com.cherepavel.vpndetector.model.TrackedApp
import org.json.JSONArray
import java.net.HttpURLConnection
import java.net.URL
import androidx.core.content.edit

object TrackedAppsRepository {

    private const val APPS_URL =
        "https://raw.githubusercontent.com/cherepavel/VPN-Detector/main/tracked_apps.json"
    private const val PREFS_NAME = "vpn_detector"
    private const val PREFS_KEY = "tracked_apps_json"
    private const val TIMEOUT_MS = 5_000

    @Volatile private var cached: List<TrackedApp>? = null

    /** Fetch from remote and update cache. Call from a background thread. */
    fun refresh(context: Context) {
        try {
            val json = fetch()
            val apps = parse(json)
            cached = apps
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit { putString(PREFS_KEY, json) }
        } catch (_: Exception) {
        }
    }

    /** Return cached → SharedPreferences → bundled fallback. */
    fun get(context: Context): List<TrackedApp> {
        cached?.let { return it }
        val stored = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(PREFS_KEY, null)
        if (stored != null) {
            return parse(stored).also { cached = it }
        }
        return fallback
    }

    private fun fetch(): String {
        val connection = URL(APPS_URL).openConnection() as HttpURLConnection
        connection.connectTimeout = TIMEOUT_MS
        connection.readTimeout = TIMEOUT_MS
        return try {
            connection.inputStream.bufferedReader().use { it.readText() }
        } finally {
            connection.disconnect()
        }
    }

    private fun parse(json: String): List<TrackedApp> {
        val array = JSONArray(json)
        return (0 until array.length()).map { i ->
            val obj = array.getJSONObject(i)
            TrackedApp(
                packageName = obj.getString("packageName"),
                label = obj.getString("label")
            )
        }
    }

    private val fallback = listOf(
        TrackedApp("com.github.dyhkwong.sagernet", "ExclaveVPN"),
        TrackedApp("com.v2ray.ang", "v2rayNG"),
        TrackedApp("org.amnezia.awg", "AmneziaWG"),
        TrackedApp("org.amnezia.vpn", "Amnezia VPN"),
        TrackedApp("de.blinkt.openvpn", "OpenVPN for Android"),
        TrackedApp("net.openvpn.openvpn", "OpenVPN Connect"),
        TrackedApp("com.wireguard.android", "WireGuard"),
        TrackedApp("com.cloudflare.onedotonedotonedotone", "Cloudflare WARP"),
        TrackedApp("com.psiphon3", "Psiphon"),
        TrackedApp("app.hiddify.com", "Hiddify"),
        TrackedApp("io.nekohasekai.sfa", "SFA"),
        TrackedApp("com.nordvpn.android", "NordVPN"),
        TrackedApp("com.expressvpn.vpn", "ExpressVPN"),
        TrackedApp("com.protonvpn.android", "Proton VPN"),
        TrackedApp("ch.protonvpn.android", "Proton VPN (legacy package)"),
        TrackedApp("free.vpn.unblock.proxy.turbovpn", "Turbo VPN"),
        TrackedApp("com.zaneschepke.wireguardautotunnel", "WG Tunnel"),
        TrackedApp("moe.nb4a", "NekoBox"),
        TrackedApp("fr.husi", "husi"),
        TrackedApp("com.outline.android", "Outline"),
        TrackedApp("xyz.safetyvpn.app", "SafetyVPN"),
        TrackedApp("net.mullvad.mullvadvpn", "Mullvad VPN"),
        TrackedApp("org.torproject.android", "Orbot")
    )
}
