package com.cherepavel.vpndetector.detector.antivpn

import java.io.File
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * Scans an installed APK for byte-level signatures from [AntiVpnSignatures]
 * and returns an aggregate score together with the list of signals that
 * fired.
 *
 * Security / privacy properties this class is responsible for:
 *
 *  * Runs **entirely offline.** No network I/O, no JNI, no reflection into
 *    other processes — it only opens files that the OS already lets the
 *    caller read (the base APK path returned by `PackageManager`).
 *  * **Bounded in time and memory.** Each dex/lib entry is read in 64 KiB
 *    chunks up to [MAX_ENTRY_BYTES]. Larger entries are skipped rather
 *    than buffered into RAM. The scanner also honours a per-package
 *    total byte budget ([MAX_TOTAL_BYTES_PER_APK]) so a pathological
 *    multi-dex app can't lock up the UI thread.
 *  * **Case-sensitive exact matching.** We are looking for framework
 *    identifiers and hard-coded string literals, which are both
 *    case-stable; avoiding normalization keeps false positives low.
 */
class DexSignatureScanner(
    private val dexSignatures: List<AntiVpnSignatures.Signature> = AntiVpnSignatures.dexSignatures,
    private val nativeSignatures: List<AntiVpnSignatures.Signature> = AntiVpnSignatures.nativeSignatures
) {

    companion object {
        /** Hard limit on a single DEX/SO entry we are willing to scan. */
        internal const val MAX_ENTRY_BYTES: Long = 32L * 1024 * 1024

        /** Hard limit on total bytes scanned per APK. */
        internal const val MAX_TOTAL_BYTES_PER_APK: Long = 96L * 1024 * 1024

        /** Read buffer size for streaming zip entries through the matcher. */
        private const val CHUNK_SIZE: Int = 64 * 1024

        /**
         * The maximum substring length we might need to match across a
         * chunk boundary. We tail-carry this many trailing bytes into the
         * next chunk so that a signature straddling the boundary is still
         * found.
         */
        private val OVERLAP: Int =
            (AntiVpnSignatures.dexSignatures + AntiVpnSignatures.nativeSignatures)
                .maxOf { it.pattern.size } - 1
    }

    data class ScanResult(
        val score: Int,
        val matches: List<AntiVpnSignatures.Signature>,
        val bytesScanned: Long,
        val skipped: List<String>
    )

    /**
     * Scan an APK at [apkPath]. Returns an empty score if the file cannot
     * be opened (e.g. system app with restricted access) — errors are
     * reported via [ScanResult.skipped], never thrown, so a single bad
     * package cannot abort the whole run.
     */
    fun scanApk(apkPath: String): ScanResult {
        val file = File(apkPath)
        if (!file.exists() || !file.canRead()) {
            return ScanResult(0, emptyList(), 0, listOf("unreadable: $apkPath"))
        }

        val matched = linkedMapOf<String, AntiVpnSignatures.Signature>()
        val skipped = mutableListOf<String>()
        var totalScanned: Long = 0

        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) continue

                    val sigsToApply: List<AntiVpnSignatures.Signature>? = when {
                        entry.name.endsWith(".dex", ignoreCase = true) -> dexSignatures
                        entry.name.startsWith("lib/") && entry.name.endsWith(".so") -> nativeSignatures
                        else -> null
                    } ?: continue

                    if (entry.size > MAX_ENTRY_BYTES) {
                        skipped.add("too-large:${entry.name}")
                        continue
                    }

                    if (totalScanned >= MAX_TOTAL_BYTES_PER_APK) {
                        skipped.add("budget-exhausted:${entry.name}")
                        continue
                    }

                    zip.getInputStream(entry).use { input ->
                        val scanned = scanStream(input, sigsToApply!!, matched)
                        totalScanned += scanned
                    }
                }
            }
        } catch (e: Throwable) {
            skipped.add("error:${e.javaClass.simpleName}:${e.message ?: ""}")
        }

        val score = matched.values.sumOf { it.weight }
        return ScanResult(
            score = score,
            matches = matched.values.toList(),
            bytesScanned = totalScanned,
            skipped = skipped
        )
    }

    /**
     * Streams [input] in chunks, applying a Boyer-Moore-style search for
     * every signature. Found signatures are added to [collector] (keyed
     * by label so duplicates in multi-dex apps only count once).
     */
    private fun scanStream(
        input: InputStream,
        signatures: List<AntiVpnSignatures.Signature>,
        collector: LinkedHashMap<String, AntiVpnSignatures.Signature>
    ): Long {
        val buffer = ByteArray(CHUNK_SIZE + OVERLAP.coerceAtLeast(0))
        var tailSize = 0 // carried over from previous chunk
        var totalRead: Long = 0

        while (true) {
            val want = buffer.size - tailSize
            val read = input.read(buffer, tailSize, want)
            if (read <= 0) break

            val dataSize = tailSize + read
            totalRead += read

            for (sig in signatures) {
                if (collector.containsKey(sig.label)) continue
                if (indexOf(buffer, dataSize, sig.pattern) >= 0) {
                    collector[sig.label] = sig
                }
            }

            // Carry the last OVERLAP bytes into the next chunk so a
            // pattern straddling the boundary is still matched.
            val carry = OVERLAP.coerceAtMost(dataSize)
            if (carry > 0) {
                System.arraycopy(buffer, dataSize - carry, buffer, 0, carry)
            }
            tailSize = carry
        }

        return totalRead
    }

    /**
     * Plain byte-level substring search. Kept intentionally simple:
     * signatures are short (≤ 32 bytes) and the data windows are small,
     * so a naive O(n·m) scan is faster in practice than building a
     * Boyer-Moore table for every call.
     */
    private fun indexOf(haystack: ByteArray, haystackSize: Int, needle: ByteArray): Int {
        val n = needle.size
        if (n == 0 || haystackSize < n) return -1
        val first = needle[0]
        val maxStart = haystackSize - n
        var i = 0
        while (i <= maxStart) {
            if (haystack[i] == first) {
                var j = 1
                while (j < n && haystack[i + j] == needle[j]) j++
                if (j == n) return i
            }
            i++
        }
        return -1
    }
}
