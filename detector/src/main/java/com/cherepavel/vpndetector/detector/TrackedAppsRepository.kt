package com.cherepavel.vpndetector.detector

import android.content.Context
import com.cherepavel.vpndetector.model.TrackedApp
import org.json.JSONArray

object TrackedAppsRepository {

    @Volatile
    private var cached: List<TrackedApp>? = null

    private const val FILE_NAME = "tracked_apps.json"

    fun get(context: Context): List<TrackedApp> {
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
}

