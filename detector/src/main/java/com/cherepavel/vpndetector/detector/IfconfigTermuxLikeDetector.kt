package com.cherepavel.vpndetector.detector

data class KernelRoutesResult(
    val routes: List<String>,
    val error: String? = null
)

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

    fun detectKernelRoutes(): KernelRoutesResult {
        if (!libraryLoaded) return KernelRoutesResult(emptyList(), "Native library failed to load")
        return try {
            KernelRoutesResult(getKernelRoutesNative().toList())
        } catch (e: Throwable) {
            KernelRoutesResult(emptyList(), "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    fun detectKernelIpv6Routes(): KernelRoutesResult {
        if (!libraryLoaded) return KernelRoutesResult(emptyList(), "Native library failed to load")
        return try {
            KernelRoutesResult(getKernelIpv6RoutesNative().toList())
        } catch (e: Throwable) {
            KernelRoutesResult(emptyList(), "${e.javaClass.simpleName}: ${e.message}")
        }
    }
}
