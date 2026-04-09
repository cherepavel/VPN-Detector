package com.cherepavel.vpndetector.ui

data class DetailSection(
    val title: String,
    val body: String,
    val state: SignalState = SignalState.NEUTRAL
)

data class DetectionReport(
    val overallTitle: String,
    val overallSummary: String,
    val overallExplanation: String,
    val overallState: SignalState,

    val transportCardState: SignalState,
    val transportStateText: String,
    val transportSubtitle: String,
    val transportAnyValue: String,
    val transportActiveValue: String,
    val transportAnyDetected: Boolean,
    val transportActiveDetected: Boolean,

    val apiSignals: List<SignalItem>,
    val nativeSignal: SignalItem,
    val nativeDetails: String,
    val extraSections: List<DetailSection>,
    val javaSignal: SignalItem,
    val knownAppsText: String
)
