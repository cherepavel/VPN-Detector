package com.cherepavel.vpndetector.detector

import java.net.InetSocketAddress
import java.net.Socket

/**
 * Detects local proxy processes (SOCKS5/HTTP) that tunnel traffic without using VpnService.
 * Typical tools: Shadowsocks, Clash, V2Ray in proxy-only mode, Tor.
 *
 * Connects to 127.0.0.1 on known proxy ports with a short timeout.
 * Loopback access does not require the INTERNET permission.
 * Must be called from a background thread.
 */
class LocalProxyDetector {

    fun detect(): List<String> {
        return PROXY_PORTS.mapNotNull { (port, label) ->
            if (isPortOpen(port)) "$label (localhost:$port)" else null
        }
    }

    private fun isPortOpen(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), TIMEOUT_MS)
                true
            }
        } catch (_: Throwable) {
            false
        }
    }

    companion object {
        private const val TIMEOUT_MS = 150

        private val PROXY_PORTS = listOf(
            1080  to "SOCKS5",
            1081  to "SOCKS5",
            8080  to "HTTP proxy",
            8118  to "Privoxy",
            7890  to "Clash (HTTP)",
            7891  to "Clash (SOCKS5)",
            10808 to "V2Ray (SOCKS5)",
            10809 to "V2Ray (HTTP)",
            2080  to "V2Ray",
            9050  to "Tor",
            9150  to "Tor Browser",
        )
    }
}
