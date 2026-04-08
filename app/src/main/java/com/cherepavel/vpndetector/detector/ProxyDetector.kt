package com.cherepavel.vpndetector.detector

import android.content.Context
import android.net.ConnectivityManager
import android.net.ProxyInfo

data class ProxyDetectionResult(
    val systemProxy: String?,
    val networkProxy: String?,
    val javaHttpProxy: String?,
    val javaHttpsProxy: String?
) {
    val anyProxy: Boolean
        get() = systemProxy != null || networkProxy != null ||
                javaHttpProxy != null || javaHttpsProxy != null

    fun summary(): String? {
        val parts = buildList {
            systemProxy?.let { add("system: $it") }
            networkProxy?.takeIf { it != systemProxy }?.let { add("network: $it") }
            javaHttpProxy?.let { add("http: $it") }
            javaHttpsProxy?.takeIf { it != javaHttpProxy }?.let { add("https: $it") }
        }
        return if (parts.isEmpty()) null else parts.joinToString("\n")
    }
}

class ProxyDetector(private val context: Context) {

    fun detect(): ProxyDetectionResult {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        @Suppress("DEPRECATION")
        val systemProxy = cm.defaultProxy?.toSummary()

        val activeNetwork = cm.activeNetwork
        val networkProxy = activeNetwork
            ?.let(cm::getLinkProperties)
            ?.httpProxy
            ?.toSummary()

        val javaHttpHost = System.getProperty("http.proxyHost")
        val javaHttpPort = System.getProperty("http.proxyPort")
        val javaHttpProxy = javaHttpHost
            ?.takeIf { it.isNotBlank() }
            ?.let { "$it:${javaHttpPort ?: "?"}" }

        val javaHttpsHost = System.getProperty("https.proxyHost")
        val javaHttpsPort = System.getProperty("https.proxyPort")
        val javaHttpsProxy = javaHttpsHost
            ?.takeIf { it.isNotBlank() }
            ?.let { "$it:${javaHttpsPort ?: "?"}" }

        return ProxyDetectionResult(
            systemProxy = systemProxy,
            networkProxy = networkProxy,
            javaHttpProxy = javaHttpProxy,
            javaHttpsProxy = javaHttpsProxy
        )
    }

    private fun ProxyInfo.toSummary(): String? {
        val h = host?.takeIf { it.isNotBlank() } ?: return null
        return "$h:$port"
    }
}
