package com.cherepavel.vpndetector.detector

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

class DynamicVpnAppsDetector(private val context: Context) {

    /** Apps that export a service with action android.net.VpnService. */
    fun detectByIntent(): List<String> {
        return try {
            context.packageManager
                .queryIntentServices(Intent("android.net.VpnService"), 0)
                .map { it.serviceInfo.packageName }
                .distinct()
                .sorted()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /**
     * Apps that declare a service protected by android.permission.BIND_VPN_SERVICE.
     * This catches VPN apps that don't export the service with a standard action.
     *
     * Requires QUERY_ALL_PACKAGES or a matching <queries> element on API 30+.
     */
    fun detectByServicePermission(): List<String> {
        return try {
            val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getInstalledPackages(
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SERVICES.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstalledPackages(PackageManager.GET_SERVICES)
            }
            packages
                .filter { pkg ->
                    pkg.services?.any { svc ->
                        svc.permission == "android.permission.BIND_VPN_SERVICE"
                    } == true
                }
                .map { it.packageName }
                .distinct()
                .sorted()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    /** Combined result: union of both detection methods, deduped. */
    fun detect(): List<String> {
        return (detectByIntent() + detectByServicePermission())
            .distinct()
            .sorted()
    }
}
