package com.cherepavel.vpndetector.detector

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.cherepavel.vpndetector.model.TrackedApp

data class TrackedAppsResult(
    val installed: List<TrackedApp>,
    val errors: Map<String, String>
)

class TrackedAppsDetector(
    private val context: Context
) {
    fun detect(): TrackedAppsResult {
        val installed = mutableListOf<TrackedApp>()
        val errors = mutableMapOf<String, String>()

        for (app in TRACKED_APPS) {
            when (val result = checkApp(app.packageName)) {
                CheckResult.Installed -> installed.add(app)
                CheckResult.NotInstalled -> Unit
                is CheckResult.Error -> errors[app.packageName] = result.message
            }
        }

        return TrackedAppsResult(installed = installed, errors = errors)
    }

    private sealed class CheckResult {
        object Installed : CheckResult()
        object NotInstalled : CheckResult()
        data class Error(val message: String) : CheckResult()
    }

    private fun checkApp(packageName: String): CheckResult {
        return try {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0)
            }
            CheckResult.Installed
        } catch (_: PackageManager.NameNotFoundException) {
            CheckResult.NotInstalled
        } catch (e: Throwable) {
            CheckResult.Error("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    companion object {
        private val TRACKED_APPS = listOf(
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
            TrackedApp("free.vpn.unblock.proxy.turbovpn", "Turbo VPN"),
            TrackedApp("com.zaneschepke.wireguardautotunnel", "WG Tunnel"),
            TrackedApp("moe.nb4a", "NekoBox"),
            TrackedApp("fr.husi", "husi")
        )
    }
}
