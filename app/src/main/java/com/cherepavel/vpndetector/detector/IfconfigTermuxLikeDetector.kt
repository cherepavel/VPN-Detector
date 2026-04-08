package com.cherepavel.vpndetector.detector

object IfconfigTermuxLikeDetector {

    private var libraryLoaded = false

    init {
        libraryLoaded = try {
            System.loadLibrary("ifconfigdetector")
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    external fun getInterfacesNative(): Array<String>
    external fun getKernelRoutesNative(): Array<String>
    external fun getKernelIpv6RoutesNative(): Array<String>

    fun detect(): IfconfigTermuxLikeResult {
        if (!libraryLoaded) {
            return IfconfigTermuxLikeResult(
                vpnLikely = false,
                matchedInterfaces = emptyList(),
                allInterfaces = emptyList(),
                nativeError = "Native library failed to load"
            )
        }

        val allBlocks: List<String>
        try {
            allBlocks = getInterfacesNative().toList()
        } catch (e: Throwable) {
            return IfconfigTermuxLikeResult(
                vpnLikely = false,
                matchedInterfaces = emptyList(),
                allInterfaces = emptyList(),
                nativeError = "getInterfacesNative failed: ${e.javaClass.simpleName}: ${e.message}"
            )
        }

        val matched = allBlocks.filter { block ->
            val firstLine = block.lineSequence().firstOrNull().orEmpty()
            TunnelNameMatcher.looksLikeTunnelName(firstLine.substringBefore(':').trim())
        }

        return IfconfigTermuxLikeResult(
            vpnLikely = matched.isNotEmpty(),
            matchedInterfaces = matched,
            allInterfaces = allBlocks,
            nativeError = null
        )
    }

    fun detectKernelRoutes(): List<String> {
        if (!libraryLoaded) return emptyList()
        return try {
            getKernelRoutesNative().toList()
        } catch (_: Throwable) {
            emptyList()
        }
    }

    fun detectKernelIpv6Routes(): List<String> {
        if (!libraryLoaded) return emptyList()
        return try {
            getKernelIpv6RoutesNative().toList()
        } catch (_: Throwable) {
            emptyList()
        }
    }
}
