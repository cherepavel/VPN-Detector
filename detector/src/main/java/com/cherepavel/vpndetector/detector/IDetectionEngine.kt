package com.cherepavel.vpndetector.detector

import com.cherepavel.vpndetector.model.DetectionSnapshot

interface IDetectionEngine {
    fun detect(): DetectionSnapshot
}
