package com.cherepavel.vpndetector

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.Uri
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.widget.NestedScrollView
import androidx.lifecycle.lifecycleScope
import com.cherepavel.vpndetector.detector.DetectionEngine
import com.cherepavel.vpndetector.model.DetectionSnapshot
import com.cherepavel.vpndetector.ui.DetectionReport
import com.cherepavel.vpndetector.ui.ReportExportFormatter
import com.cherepavel.vpndetector.ui.ReportFormatter
import com.cherepavel.vpndetector.ui.SignalItem
import com.cherepavel.vpndetector.ui.SignalState
import com.cherepavel.vpndetector.util.nowString
import java.io.OutputStreamWriter
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var cardStatus: LinearLayout
    private lateinit var textVpnStatus: TextView
    private lateinit var textVpnSummary: TextView
    private lateinit var textVpnExplanation: TextView
    private lateinit var buttonRefresh: Button
    private lateinit var buttonReport: Button
    private lateinit var textLastUpdate: TextView

    private lateinit var cardTransportVpn: LinearLayout
    private lateinit var textTransportState: TextView
    private lateinit var textTransportSubtitle: TextView
    private lateinit var textTransportAnyValue: TextView
    private lateinit var textTransportActiveValue: TextView

    private lateinit var cardApiSignal1: LinearLayout
    private lateinit var cardApiSignal2: LinearLayout
    private lateinit var textApiSignalTitle1: TextView
    private lateinit var textApiSignalTitle2: TextView
    private lateinit var textApiSignalSource1: TextView
    private lateinit var textApiSignalSource2: TextView
    private lateinit var textApiSignalValue1: TextView
    private lateinit var textApiSignalValue2: TextView
    private lateinit var textApiSignalHint1: TextView
    private lateinit var textApiSignalHint2: TextView

    private lateinit var cardNativeSignal: LinearLayout
    private lateinit var textNativeSignalTitle: TextView
    private lateinit var textNativeSignalSource: TextView
    private lateinit var textNativeSignalValue: TextView
    private lateinit var textNativeSignalHint: TextView
    private lateinit var textNativeDetails: TextView
    private lateinit var scrollNativeDetails: NestedScrollView

    private lateinit var cardJavaSignal: LinearLayout
    private lateinit var textJavaSignalTitle: TextView
    private lateinit var textJavaSignalSource: TextView
    private lateinit var textJavaSignalValue: TextView
    private lateinit var textJavaSignalHint: TextView

    private lateinit var textKnownApps: TextView

    private lateinit var apiSignalCards: List<LinearLayout>
    private lateinit var apiSignalTitles: List<TextView>
    private lateinit var apiSignalSources: List<TextView>
    private lateinit var apiSignalValues: List<TextView>
    private lateinit var apiSignalHints: List<TextView>

    private val connectivityManager by lazy {
        getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }
    private val detectionEngine by lazy { DetectionEngine(this, connectivityManager) }

    private var lastExportText: String = ""
    private var detectionJob: Job? = null
    private var scheduledRefreshJob: Job? = null
    private var networkCallbackRegistered = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = scheduleRefresh()

        override fun onLost(network: Network) = scheduleRefresh()

        override fun onCapabilitiesChanged(
            network: Network,
            networkCapabilities: NetworkCapabilities
        ) = scheduleRefresh()

        override fun onLinkPropertiesChanged(
            network: Network,
            linkProperties: LinkProperties
        ) = scheduleRefresh()
    }

    private val createDocumentLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
            if (uri != null) {
                saveReportToUri(uri)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.rootLayout)) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(
                view.paddingLeft,
                bars.top + 16,
                view.paddingRight,
                bars.bottom + 16
            )
            insets
        }

        bindViews()
        setupListeners()
        registerNetworkCallback()
        refreshUi()
    }

    override fun onDestroy() {
        unregisterNetworkCallback()
        detectionJob?.cancel()
        scheduledRefreshJob?.cancel()
        super.onDestroy()
    }

    private fun bindViews() {
        cardStatus = findViewById(R.id.cardStatus)
        textVpnStatus = findViewById(R.id.textVpnStatus)
        textVpnSummary = findViewById(R.id.textVpnSummary)
        textVpnExplanation = findViewById(R.id.textVpnExplanation)
        buttonRefresh = findViewById(R.id.buttonRefresh)
        buttonReport = findViewById(R.id.buttonReport)
        textLastUpdate = findViewById(R.id.textLastUpdate)

        cardTransportVpn = findViewById(R.id.cardTransportVpn)
        textTransportState = findViewById(R.id.textTransportState)
        textTransportSubtitle = findViewById(R.id.textTransportSubtitle)
        textTransportAnyValue = findViewById(R.id.textTransportAnyValue)
        textTransportActiveValue = findViewById(R.id.textTransportActiveValue)

        cardApiSignal1 = findViewById(R.id.cardApiSignal1)
        cardApiSignal2 = findViewById(R.id.cardApiSignal2)
        textApiSignalTitle1 = findViewById(R.id.textApiSignalTitle1)
        textApiSignalTitle2 = findViewById(R.id.textApiSignalTitle2)
        textApiSignalSource1 = findViewById(R.id.textApiSignalSource1)
        textApiSignalSource2 = findViewById(R.id.textApiSignalSource2)
        textApiSignalValue1 = findViewById(R.id.textApiSignalValue1)
        textApiSignalValue2 = findViewById(R.id.textApiSignalValue2)
        textApiSignalHint1 = findViewById(R.id.textApiSignalHint1)
        textApiSignalHint2 = findViewById(R.id.textApiSignalHint2)

        cardNativeSignal = findViewById(R.id.cardNativeSignal)
        textNativeSignalTitle = findViewById(R.id.textNativeSignalTitle)
        textNativeSignalSource = findViewById(R.id.textNativeSignalSource)
        textNativeSignalValue = findViewById(R.id.textNativeSignalValue)
        textNativeSignalHint = findViewById(R.id.textNativeSignalHint)
        textNativeDetails = findViewById(R.id.textNativeDetails)
        scrollNativeDetails = findViewById(R.id.scrollNativeDetails)

        cardJavaSignal = findViewById(R.id.cardJavaSignal)
        textJavaSignalTitle = findViewById(R.id.textJavaSignalTitle)
        textJavaSignalSource = findViewById(R.id.textJavaSignalSource)
        textJavaSignalValue = findViewById(R.id.textJavaSignalValue)
        textJavaSignalHint = findViewById(R.id.textJavaSignalHint)

        textKnownApps = findViewById(R.id.textKnownApps)

        apiSignalCards = listOf(cardApiSignal1, cardApiSignal2)
        apiSignalTitles = listOf(textApiSignalTitle1, textApiSignalTitle2)
        apiSignalSources = listOf(textApiSignalSource1, textApiSignalSource2)
        apiSignalValues = listOf(textApiSignalValue1, textApiSignalValue2)
        apiSignalHints = listOf(textApiSignalHint1, textApiSignalHint2)
    }

    private fun setupListeners() {
        buttonRefresh.setOnClickListener { refreshUi() }

        buttonReport.setOnClickListener {
            showReportActions()
        }

        scrollNativeDetails.setOnTouchListener { view, event ->
            when (event.actionMasked) {
                MotionEvent.ACTION_DOWN,
                MotionEvent.ACTION_MOVE -> {
                    view.parent?.requestDisallowInterceptTouchEvent(true)
                }

                MotionEvent.ACTION_UP,
                MotionEvent.ACTION_CANCEL -> {
                    view.parent?.requestDisallowInterceptTouchEvent(false)
                }
            }
            false
        }
    }

    private data class DetectionOutput(
        val report: DetectionReport,
        val snapshot: DetectionSnapshot,
        val exportText: String
    )

    private fun refreshUi() {
        detectionJob?.cancel()
        buttonRefresh.isEnabled = false
        detectionJob = lifecycleScope.launch {
            val output = withContext(Dispatchers.IO) { runDetection() }
            renderReport(output.report)
            renderLastUpdate()
            lastExportText = output.exportText
            buttonRefresh.isEnabled = true
        }
    }

    private fun scheduleRefresh() {
        scheduledRefreshJob?.cancel()
        scheduledRefreshJob = lifecycleScope.launch {
            delay(250)
            refreshUi()
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallbackRegistered) return
        val request = NetworkRequest.Builder().build()
        runCatching {
            connectivityManager.registerNetworkCallback(request, networkCallback)
        }.onSuccess {
            networkCallbackRegistered = true
        }
    }

    private fun unregisterNetworkCallback() {
        if (!networkCallbackRegistered) return
        runCatching {
            connectivityManager.unregisterNetworkCallback(networkCallback)
        }
        networkCallbackRegistered = false
    }

    private fun runDetection(): DetectionOutput {
        val snapshot = detectionEngine.detect()
        val report = ReportFormatter.build(snapshot)

        val exportText = ReportExportFormatter.buildText(
            ReportExportFormatter.ExportInput(
                report = report,
                snapshot = snapshot
            )
        )

        return DetectionOutput(
            report = report,
            snapshot = snapshot,
            exportText = exportText
        )
    }

    private fun renderReport(report: DetectionReport) {
        textVpnStatus.text = report.overallTitle
        textVpnSummary.text = report.overallSummary
        textVpnExplanation.text = report.overallExplanation

        applySectionCardBackground(cardStatus)
        applyStatusTextColor(textVpnStatus, report.overallState)

        textTransportState.text = report.transportStateText
        textTransportSubtitle.text = report.transportSubtitle
        textTransportAnyValue.text = report.transportAnyValue
        textTransportActiveValue.text = report.transportActiveValue

        applyInnerCardBackground(cardTransportVpn)
        applyValueTextColor(textTransportState, report.transportCardState)

        applyTransportBadgeBackground(
            view = textTransportAnyValue,
            isDetected = report.transportAnyValue == "DETECTED"
        )
        applyTransportBadgeBackground(
            view = textTransportActiveValue,
            isDetected = report.transportActiveValue == "DETECTED"
        )

        renderApiSignals(report.apiSignals)

        bindSignalCard(
            card = cardNativeSignal,
            titleView = textNativeSignalTitle,
            sourceView = textNativeSignalSource,
            valueView = textNativeSignalValue,
            hintView = textNativeSignalHint,
            item = report.nativeSignal
        )
        textNativeDetails.text = report.nativeDetails

        bindSignalCard(
            card = cardJavaSignal,
            titleView = textJavaSignalTitle,
            sourceView = textJavaSignalSource,
            valueView = textJavaSignalValue,
            hintView = textJavaSignalHint,
            item = report.javaSignal
        )

        textKnownApps.text = report.knownAppsText
    }

    private fun renderApiSignals(signals: List<SignalItem>) {
        for (index in apiSignalCards.indices) {
            val hasItem = index < signals.size
            val card = apiSignalCards[index]

            card.visibility = if (hasItem) View.VISIBLE else View.GONE
            if (!hasItem) continue

            bindSignalCard(
                card = card,
                titleView = apiSignalTitles[index],
                sourceView = apiSignalSources[index],
                valueView = apiSignalValues[index],
                hintView = apiSignalHints[index],
                item = signals[index]
            )
        }
    }

    private fun bindSignalCard(
        card: LinearLayout,
        titleView: TextView,
        sourceView: TextView,
        valueView: TextView,
        hintView: TextView,
        item: SignalItem
    ) {
        titleView.text = item.title
        sourceView.text = item.source
        valueView.text = item.value
        hintView.text = item.hint

        applyInnerCardBackground(card)
        applyValueTextColor(valueView, item.state)
    }

    private fun renderLastUpdate() {
        textLastUpdate.text = "Last update: ${nowString()}"
    }

    private fun showReportActions() {
        if (lastExportText.isBlank()) {
            refreshUi()
        }

        val options = arrayOf("Share report", "Save report to file")

        AlertDialog.Builder(this)
            .setTitle("Report actions")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> shareReport()
                    1 -> saveReport()
                }
            }
            .show()
    }

    private fun shareReport() {
        if (lastExportText.isBlank()) return

        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "VPN Detector Report")
            putExtra(Intent.EXTRA_TEXT, lastExportText)
        }

        startActivity(Intent.createChooser(sendIntent, "Share report"))
    }

    private fun saveReport() {
        if (lastExportText.isBlank()) return

        val fileName = "vpn_detector_report_${nowString("yyyyMMdd_HHmmss")}.txt"
        createDocumentLauncher.launch(fileName)
    }

    private fun saveReportToUri(uri: Uri) {
        if (lastExportText.isBlank()) return

        contentResolver.openOutputStream(uri)?.use { outputStream ->
            OutputStreamWriter(outputStream).use { writer ->
                writer.write(lastExportText)
                writer.flush()
            }
        }
    }

    private fun applySectionCardBackground(card: LinearLayout) {
        card.setBackgroundResource(R.drawable.bg_card_surface)
    }

    private fun applyInnerCardBackground(card: LinearLayout) {
        card.setBackgroundResource(R.drawable.bg_card_inner)
    }

    private fun applyValueTextColor(view: TextView, state: SignalState) {
        view.setTextColor(state.toSignalColor())
    }

    private fun applyStatusTextColor(view: TextView, state: SignalState) {
        view.setTextColor(state.toSignalColor())
    }

    private fun applyTransportBadgeBackground(view: TextView, isDetected: Boolean) {
        view.setBackgroundResource(
            if (isDetected) {
                R.drawable.bg_signal_positive
            } else {
                R.drawable.bg_signal_negative
            }
        )
    }

    private fun SignalState.toSignalColor(): Int {
        return when (this) {
            SignalState.POSITIVE -> getColorCompat(R.color.signal_red)
            SignalState.NEGATIVE -> getColorCompat(R.color.signal_green)
            SignalState.WARNING -> getColorCompat(R.color.signal_orange)
            SignalState.NEUTRAL -> getColorCompat(R.color.signal_gray)
            SignalState.SEMI -> getColorCompat(R.color.signal_blue)
        }
    }

    private fun getColorCompat(colorRes: Int): Int {
        return ContextCompat.getColor(this, colorRes)
    }
}
