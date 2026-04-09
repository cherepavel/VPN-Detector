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

        for (app in TrackedAppsRepository.get(context)) {
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

}
