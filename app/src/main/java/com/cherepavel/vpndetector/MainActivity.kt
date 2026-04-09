package com.cherepavel.vpndetector

import android.annotation.SuppressLint
import android.content.Intent
import android.net.ConnectivityManager
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
import com.cherepavel.vpndetector.detector.IDetectionEngine
import com.cherepavel.vpndetector.ui.DetailSection
import com.cherepavel.vpndetector.ui.DetectionReport
import com.cherepavel.vpndetector.ui.ReportFormatter
import com.cherepavel.vpndetector.ui.SignalItem
import com.cherepavel.vpndetector.ui.SignalState
import com.cherepavel.vpndetector.ui.export.ReportExportBuilder
import com.cherepavel.vpndetector.ui.export.ReportExportFormatter
import com.cherepavel.vpndetector.util.nowString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter

class MainActivity : AppCompatActivity() {

    private lateinit var cardStatus: LinearLayout
    private lateinit var textVpnStatus: TextView
    private lateinit var textVpnSummary: TextView
    private lateinit var textVpnExplanation: TextView
    private lateinit var buttonRefresh: Button
    private lateinit var buttonReport: Button
    private lateinit var textLastUpdate: TextView
    private lateinit var textVersion: TextView
    private lateinit var textFooterInfo: TextView

    private lateinit var cardTransportVpn: LinearLayout
    private lateinit var textTransportState: TextView
    private lateinit var textTransportSubtitle: TextView
    private lateinit var textTransportAnyValue: TextView
    private lateinit var textTransportActiveValue: TextView

    private lateinit var cardApiSignal1: LinearLayout
    private lateinit var cardApiSignal2: LinearLayout

    private lateinit var cardNativeSignal: LinearLayout
    private lateinit var textNativeDetails: TextView
    private lateinit var scrollNativeDetails: NestedScrollView

    private lateinit var containerExtraSections: LinearLayout

    private lateinit var cardJavaSignal: LinearLayout

    private lateinit var textKnownApps: TextView

    private lateinit var apiSignalCards: List<LinearLayout>

    private val connectivityManager by lazy {
        getSystemService(CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    private val detectionEngine: IDetectionEngine by lazy {
        DetectionEngine(this, connectivityManager)
    }

    private var lastExportText: String = ""
    private var detectionJob: Job? = null

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
        renderVersion()
        renderFooter()
        setupListeners()
        refreshUi()
    }

    override fun onDestroy() {
        detectionJob?.cancel()
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
        textVersion = findViewById(R.id.textVersion)
        textFooterInfo = findViewById(R.id.textFooterInfo)

        cardTransportVpn = findViewById(R.id.cardTransportVpn)
        textTransportState = findViewById(R.id.textTransportState)
        textTransportSubtitle = findViewById(R.id.textTransportSubtitle)
        textTransportAnyValue = findViewById(R.id.textTransportAnyValue)
        textTransportActiveValue = findViewById(R.id.textTransportActiveValue)

        cardApiSignal1 = findViewById(R.id.cardApiSignal1)
        cardApiSignal2 = findViewById(R.id.cardApiSignal2)

        cardNativeSignal = findViewById(R.id.cardNativeSignal)
        textNativeDetails = findViewById(R.id.textNativeDetails)
        scrollNativeDetails = findViewById(R.id.scrollNativeDetails)

        containerExtraSections = findViewById(R.id.containerExtraSections)

        cardJavaSignal = findViewById(R.id.cardJavaSignal)

        textKnownApps = findViewById(R.id.textKnownApps)

        apiSignalCards = listOf(cardApiSignal1, cardApiSignal2)
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun setupListeners() {
        buttonRefresh.setOnClickListener { refreshUi() }

        buttonReport.setOnClickListener {
            showReportActions()
        }

        textFooterInfo.setOnClickListener {
            startActivity(
                Intent(
                    Intent.ACTION_VIEW,
                    Uri.parse(getString(R.string.repo_url))
                )
            )
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
        val exportText: String
    )

    private fun refreshUi() {
        detectionJob?.cancel()
        buttonRefresh.isEnabled = false
        buttonReport.isEnabled = false

        detectionJob = lifecycleScope.launch {
            val output = withContext(Dispatchers.IO) { runDetection() }
            renderReport(output.report)
            renderLastUpdate()
            lastExportText = output.exportText
            buttonRefresh.isEnabled = true
            buttonReport.isEnabled = true
        }
    }

    private fun runDetection(): DetectionOutput {
        val snapshot = detectionEngine.detect()
        val report = ReportFormatter.build(this, snapshot)

        val exportReport = ReportExportBuilder.build(this, snapshot)
        val exportText = ReportExportFormatter.buildText(exportReport)

        return DetectionOutput(
            report = report,
            exportText = exportText
        )
    }

    private fun renderReport(report: DetectionReport) {
        textVpnStatus.text = report.overallTitle
        textVpnSummary.text = report.overallSummary
        textVpnExplanation.text = report.overallExplanation

        applySectionCardBackground(cardStatus)
        applyValueTextColor(textVpnStatus, report.overallState)

        textTransportState.text = report.transportStateText
        textTransportSubtitle.text = report.transportSubtitle
        textTransportAnyValue.text = report.transportAnyValue
        textTransportActiveValue.text = report.transportActiveValue

        applyInnerCardBackground(cardTransportVpn)
        applyValueTextColor(textTransportState, report.transportCardState)

        applyTransportBadgeBackground(
            view = textTransportAnyValue,
            isDetected = report.transportAnyDetected
        )
        applyTransportBadgeBackground(
            view = textTransportActiveValue,
            isDetected = report.transportActiveDetected
        )

        renderApiSignals(report.apiSignals)

        bindSignalCard(
            card = cardNativeSignal,
            item = report.nativeSignal
        )

        textNativeDetails.text = report.nativeDetails
        renderExtraSections(report.extraSections)

        bindSignalCard(
            card = cardJavaSignal,
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
                item = signals[index]
            )
        }
    }

    private fun renderExtraSections(sections: List<DetailSection>) {
        containerExtraSections.removeAllViews()

        for (section in sections) {
            val itemView = layoutInflater.inflate(
                R.layout.common_item_detail_section,
                containerExtraSections,
                false
            )

            val titleView = itemView.findViewById<TextView>(R.id.textDetailTitle)
            val bodyView = itemView.findViewById<TextView>(R.id.textDetailBody)

            titleView.text = section.title
            bodyView.text = section.body
            applyValueTextColor(titleView, section.state)

            containerExtraSections.addView(itemView)
        }
    }

    private fun bindSignalCard(
        card: LinearLayout,
        item: SignalItem
    ) {
        val titleView = card.findViewById<TextView>(R.id.textSignalTitle)
        val sourceView = card.findViewById<TextView>(R.id.textSignalSource)
        val valueView = card.findViewById<TextView>(R.id.textSignalValue)
        val hintView = card.findViewById<TextView>(R.id.textSignalHint)

        titleView.text = item.title
        sourceView.text = item.source
        valueView.text = item.value
        hintView.text = item.hint

        applyInnerCardBackground(card)
        applyValueTextColor(valueView, item.state)
    }

    @SuppressLint("SetTextI18n")
    private fun renderLastUpdate() {
        textLastUpdate.text = "Last update: ${nowString()}"
    }

    private fun renderVersion() {
        textVersion.text =
            "${BuildConfig.VERSION_NAME} • ${BuildConfig.GIT_HASH} • ${BuildConfig.BUILD_TYPE}"
    }

    private fun renderFooter() {
        val repoText = getString(R.string.repo_url)
            .removePrefix("https://")
            .removePrefix("http://")

        textFooterInfo.text = "${getString(R.string.source_code_label)} $repoText"
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
