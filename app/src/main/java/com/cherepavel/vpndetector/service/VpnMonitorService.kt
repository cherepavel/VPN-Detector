package com.cherepavel.vpndetector.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.cherepavel.vpndetector.MainActivity
import com.cherepavel.vpndetector.R
import com.cherepavel.vpndetector.detector.DetectionEngine
import com.cherepavel.vpndetector.detector.IDetectionEngine
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.model.DetectionStatus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VpnMonitorService : Service() {

    private val connectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    private val detectionEngine: IDetectionEngine by lazy { DetectionEngine(this) }
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    private var networkCallbackRegistered = false
    private var debounceJob: Job? = null

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = scheduleDetection()
        override fun onLost(network: Network) = scheduleDetection()
        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities
        ) = scheduleDetection()
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification("Monitoring VPN state…"))
        registerNetworkCallback()
        scheduleDetection()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        unregisterNetworkCallback()
        scope.cancel()
        super.onDestroy()
    }

    private fun scheduleDetection() {
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(DEBOUNCE_MS)
            val snapshot = withContext(Dispatchers.IO) { detectionEngine.detect() }
            updateNotification(snapshot)
        }
    }

    private fun updateNotification(snapshot: DetectionSnapshot) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(snapshot.toStatusText()))
    }

    private fun DetectionSnapshot.toStatusText(): String = when (assessment.status) {
        DetectionStatus.ACTIVE_VPN ->
            if (lockdownLikely) "VPN active — lockdown mode" else "VPN active"
        DetectionStatus.SPLIT_TUNNEL ->
            "VPN present (split tunnel / bypass)"
        DetectionStatus.VPN_LIKE ->
            "VPN-like signals detected (score ${assessment.score}/100)"
        DetectionStatus.APPS_PRESENT ->
            "No active VPN — VPN apps installed"
        DetectionStatus.NO_EVIDENCE ->
            "No VPN detected"
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
            },
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VPN Detector")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setShowWhen(false)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Monitor",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Live VPN detection status"
                setShowBadge(false)
            }
            (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallbackRegistered) return
        runCatching {
            connectivityManager.registerNetworkCallback(
                NetworkRequest.Builder().build(),
                networkCallback
            )
        }.onSuccess { networkCallbackRegistered = true }
    }

    private fun unregisterNetworkCallback() {
        if (!networkCallbackRegistered) return
        runCatching { connectivityManager.unregisterNetworkCallback(networkCallback) }
        networkCallbackRegistered = false
    }

    companion object {
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "vpn_monitor_channel"
        private const val DEBOUNCE_MS = 300L

        fun start(context: Context) {
            val intent = Intent(context, VpnMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, VpnMonitorService::class.java))
        }
    }
}
