package io.github.privacygate.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SsaidDeriverTest {

    private val key = ByteArray(32) { it.toByte() }

    @Test
    fun `sha256 known vectors`() {
        assertEquals(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            SsaidDeriver.sha256Hex(ByteArray(0)),
        )
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            SsaidDeriver.sha256Hex("abc".toByteArray()),
        )
    }

    @Test
    fun `derive is deterministic`() {
        val a = SsaidDeriver.derive(key, 0, "aabbccdd", 20700)
        val b = SsaidDeriver.derive(key, 0, "aabbccdd", 20700)
        assertEquals(a, b)
    }

    @Test
    fun `derive is sensitive to every input`() {
        val base = SsaidDeriver.derive(key, 0, "aabbccdd", 20700)

        assertNotEquals(base, SsaidDeriver.derive(key, 1, "aabbccdd", 20700))        // userId
        assertNotEquals(base, SsaidDeriver.derive(key, 0, "ccbbaa99", 20700))        // signer
        assertNotEquals(base, SsaidDeriver.derive(key, 0, "aabbccdd", 20701))        // bucket
        assertNotEquals(base, SsaidDeriver.derive(ByteArray(32) { (it + 1).toByte() }, 0, "aabbccdd", 20700)) // key
    }

    @Test
    fun `output is 16 lowercase hex chars`() {
        val v = SsaidDeriver.derive(key, 0, "aabbccdd", 20700)
        assertEquals(16, v.length)
        assertTrue(v.matches(Regex("^[0-9a-f]{16}$")))
    }

    @Test
    fun `derived value never lands on known bad values`() {
        // 大样本抽验：任何输入都不应产出坏值
        for (u in 0 until 8) {
            for (b in 20_000L until 20_010L) {
                val v = SsaidDeriver.derive(key, u, "deadbeef", b)
                assertTrue(v !in SsaidDeriver.BAD_VALUES)
            }
        }
    }

    @Test
    fun `hmac rfc4231 case 1`() {
        // RFC 4231 Test Case 1: key = 0x0b x20, data = "Hi There"
        val key = ByteArray(20) { 0x0b }
        val expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        assertEquals(expected, SsaidDeriver.hmacSha256(key, "Hi There".toByteArray()).toLowerHex())
    }

    private fun ByteArray.toLowerHex(): String = joinToString("") { "%02x".format(it) }
}
