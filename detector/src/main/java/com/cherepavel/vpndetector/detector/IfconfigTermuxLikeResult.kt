package com.cherepavel.vpndetector.detector

data class IfconfigTermuxLikeResult(
    val vpnLikely: Boolean,
    val matchedInterfaces: List<String>,
    val allInterfaces: List<String>,
    val nativeError: String? = null
)
