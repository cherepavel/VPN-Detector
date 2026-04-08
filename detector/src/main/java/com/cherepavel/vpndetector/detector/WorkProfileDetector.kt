package com.cherepavel.vpndetector.detector

import android.content.Context
import android.os.Build
import android.os.UserManager

/**
 * Detects the presence of a work/managed profile.
 *
 * VPN apps installed inside a work profile are invisible to the primary user's
 * PackageManager, so TrackedAppsDetector and DynamicVpnAppsDetector cannot see them.
 * This detector flags the limitation so it can be surfaced in the report.
 */
object WorkProfileDetector {

    data class Result(
        val hasMultipleProfiles: Boolean,
        val profileCount: Int,
        val isManagedProfile: Boolean
    )

    fun detect(context: Context): Result {
        val userManager = context.getSystemService(Context.USER_SERVICE) as UserManager

        val profileCount = runCatching { userManager.userProfiles.size }.getOrDefault(1)

        val isManagedProfile = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                userManager.isManagedProfile
            } else {
                false
            }
        }.getOrDefault(false)

        return Result(
            hasMultipleProfiles = profileCount > 1,
            profileCount = profileCount,
            isManagedProfile = isManagedProfile
        )
    }
}
