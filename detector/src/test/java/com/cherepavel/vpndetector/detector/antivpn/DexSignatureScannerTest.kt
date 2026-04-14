package com.cherepavel.vpndetector.detector.antivpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Unit tests for [DexSignatureScanner].
 *
 * We cannot build a real DEX file in a unit test, but the scanner
 * operates on raw bytes, so we can validate behaviour by constructing
 * synthetic ZIP archives whose `classes.dex` and `lib/*/lib*.so` entries
 * contain the signature strings we expect the scanner to match.
 *
 * These tests exercise three things:
 *
 *   1. That individual signature classes (strong / medium / native) are
 *      matched in the right kind of entry and not matched where they
 *      don't belong.
 *   2. That the aggregate score respects the LIKELY/POSSIBLE thresholds
 *      from [AntiVpnSignatures].
 *   3. That a stream longer than one chunk still matches a signature
 *      straddling a chunk boundary (overlap-carry logic).
 */
class DexSignatureScannerTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val scanner = DexSignatureScanner()

    @Test
    fun emptyApk_scoresZero() {
        val apk = buildApk { /* empty */ }
        val result = scanner.scanApk(apk.absolutePath)
        assertEquals(0, result.score)
        assertTrue(result.matches.isEmpty())
    }

    @Test
    fun nonExistentPath_returnsZeroAndIsSkipped() {
        val result = scanner.scanApk(tempFolder.root.absolutePath + "/missing.apk")
        assertEquals(0, result.score)
        assertTrue(result.skipped.isNotEmpty())
    }

    @Test
    fun strongSignalInDex_pushesIntoLikely() {
        val apk = buildApk {
            putEntry("classes.dex", asciiPayload("header ... NET_CAPABILITY_NOT_VPN ... TRANSPORT_VPN ... tail"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        // NET_CAPABILITY_NOT_VPN (8) + TRANSPORT_VPN (6) = 14 >= SCORE_LIKELY (10)
        assertTrue("expected score >= LIKELY, got ${result.score}", result.score >= AntiVpnSignatures.SCORE_LIKELY)
        assertTrue(result.matches.any { it.label == "NET_CAPABILITY_NOT_VPN reference" })
        assertTrue(result.matches.any { it.label == "TRANSPORT_VPN reference" })
    }

    @Test
    fun onlyWeakSignals_stayBelowPossible() {
        val apk = buildApk {
            putEntry("classes.dex", asciiPayload("isUp"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        // "isUp" weight = 1, SCORE_POSSIBLE = 5
        assertTrue("expected score < POSSIBLE, got ${result.score}", result.score < AntiVpnSignatures.SCORE_POSSIBLE)
    }

    @Test
    fun tunLiteralAlone_reachesPossible() {
        val apk = buildApk {
            putEntry("classes.dex", asciiPayload("interface name: tun0"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        // tun0 = 5 which is exactly SCORE_POSSIBLE
        assertTrue(result.score >= AntiVpnSignatures.SCORE_POSSIBLE)
        assertTrue(result.matches.any { it.label == "tun0 literal" })
    }

    @Test
    fun dexSignatures_notMatchedInNativeLib() {
        // NET_CAPABILITY_NOT_VPN is a DEX signature, not a native one.
        // Putting it in a .so must not score.
        val apk = buildApk {
            putEntry("lib/arm64-v8a/libfoo.so", asciiPayload("NET_CAPABILITY_NOT_VPN"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertEquals(0, result.score)
    }

    @Test
    fun nativeLibSignatures_matched() {
        val apk = buildApk {
            putEntry(
                "lib/arm64-v8a/libfoo.so",
                asciiPayload("uses getifaddrs and reads /proc/net/route here")
            )
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertTrue(result.matches.any { it.label == "getifaddrs in native lib" })
        assertTrue(result.matches.any { it.label == "/proc/net/route read" })
    }

    @Test
    fun randomTextFiles_areIgnored() {
        // README / resources should not be scanned.
        val apk = buildApk {
            putEntry("assets/readme.txt", asciiPayload("NET_CAPABILITY_NOT_VPN appears here but shouldn't count"))
            putEntry("res/layout/main.xml", asciiPayload("tun0"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertEquals(0, result.score)
    }

    @Test
    fun signatureStraddlingChunkBoundary_isStillMatched() {
        // Build a dex entry whose total size is larger than the scanner
        // chunk buffer, placing the signature bytes exactly on the
        // boundary between chunk N and chunk N+1.
        val chunk = 64 * 1024
        val filler = ByteArray(chunk - 5) { 'A'.code.toByte() }
        val needle = "NET_CAPABILITY_NOT_VPN".toByteArray()
        // Put filler (chunk - 5 bytes), then the needle (22 bytes) so the
        // first 5 bytes of the needle land in chunk 1 and the rest in chunk 2,
        // then some tail so we actually read into a second chunk.
        val payload = ByteArray(filler.size + needle.size + 64)
        System.arraycopy(filler, 0, payload, 0, filler.size)
        System.arraycopy(needle, 0, payload, filler.size, needle.size)

        val apk = buildApk {
            putEntry("classes.dex", payload)
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertTrue(
            "overlap carry failed: score=${result.score}, matches=${result.matches.map { it.label }}",
            result.matches.any { it.label == "NET_CAPABILITY_NOT_VPN reference" }
        )
    }

    @Test
    fun duplicateSignatureInMultiDex_countedOnce() {
        val apk = buildApk {
            putEntry("classes.dex", asciiPayload("NET_CAPABILITY_NOT_VPN"))
            putEntry("classes2.dex", asciiPayload("NET_CAPABILITY_NOT_VPN"))
            putEntry("classes3.dex", asciiPayload("NET_CAPABILITY_NOT_VPN"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertEquals(1, result.matches.count { it.label == "NET_CAPABILITY_NOT_VPN reference" })
        // Score equals the single-signal weight, not 3x of it.
        assertEquals(8, result.score)
    }

    @Test
    fun knownSdkPrefix_contributesMediumWeight() {
        val apk = buildApk {
            putEntry("classes.dex", asciiPayload("com/ipqualityscore/sdk/Client"))
        }
        val result = scanner.scanApk(apk.absolutePath)
        assertTrue(result.matches.any { it.label == "IPQualityScore SDK" })
        assertFalse(result.matches.any { it.label == "NET_CAPABILITY_NOT_VPN reference" })
    }

    // --- helpers ------------------------------------------------------------

    private fun asciiPayload(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)

    private inner class ApkBuilder(private val zos: ZipOutputStream) {
        fun putEntry(name: String, content: ByteArray) {
            zos.putNextEntry(ZipEntry(name))
            zos.write(content)
            zos.closeEntry()
        }
    }

    private fun buildApk(block: ApkBuilder.() -> Unit): File {
        val file = tempFolder.newFile("synthetic-${System.nanoTime()}.apk")
        ZipOutputStream(file.outputStream()).use { zos ->
            ApkBuilder(zos).block()
        }
        return file
    }
}
