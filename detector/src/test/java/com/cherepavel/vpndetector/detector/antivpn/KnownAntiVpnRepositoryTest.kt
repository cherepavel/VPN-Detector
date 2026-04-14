package com.cherepavel.vpndetector.detector.antivpn

import com.cherepavel.vpndetector.model.AntiVpnSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [KnownAntiVpnRepository.parse].
 *
 * The full `get(Context)` path can only run inside Android, but the JSON
 * parser itself is pure and deserves its own regression tests so malformed
 * or partial entries don't silently produce garbage at runtime.
 */
class KnownAntiVpnRepositoryTest {

    @Test
    fun parsesWellFormedEntries() {
        val json = """
            [
              {
                "packageName": "com.example.bank",
                "label": "Example Bank",
                "category": "banking",
                "severity": "high",
                "evidence": "public disclosure"
              },
              {
                "packageName": "com.example.stream",
                "label": "Example Stream",
                "category": "streaming",
                "severity": "medium",
                "evidence": ""
              }
            ]
        """.trimIndent()

        val parsed = KnownAntiVpnRepository.parse(json)

        assertEquals(2, parsed.size)
        assertEquals("com.example.bank", parsed[0].packageName)
        assertEquals(AntiVpnSeverity.HIGH, parsed[0].severity)
        assertEquals("banking", parsed[0].category)
        assertEquals("public disclosure", parsed[0].evidence)

        assertEquals(AntiVpnSeverity.MEDIUM, parsed[1].severity)
    }

    @Test
    fun unknownSeverity_defaultsToMedium() {
        val json = """
            [
              {
                "packageName": "com.example.app",
                "label": "Example",
                "category": "other",
                "severity": "weird",
                "evidence": ""
              }
            ]
        """.trimIndent()

        val parsed = KnownAntiVpnRepository.parse(json)
        assertEquals(AntiVpnSeverity.MEDIUM, parsed[0].severity)
    }

    @Test
    fun missingOptionalFields_useDefaults() {
        // packageName and label are required; category, severity, evidence all optional.
        val json = """
            [
              { "packageName": "com.example.app", "label": "Example" }
            ]
        """.trimIndent()

        val parsed = KnownAntiVpnRepository.parse(json)
        assertEquals(1, parsed.size)
        assertEquals("unknown", parsed[0].category)
        assertEquals(AntiVpnSeverity.MEDIUM, parsed[0].severity)
        assertTrue(parsed[0].evidence.isEmpty())
    }

    @Test
    fun emptyArray_returnsEmptyList() {
        val parsed = KnownAntiVpnRepository.parse("[]")
        assertTrue(parsed.isEmpty())
    }
}
