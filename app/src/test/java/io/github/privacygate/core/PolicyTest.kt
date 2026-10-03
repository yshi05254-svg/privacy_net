package io.github.privacygate.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PolicyTest {

    @Test
    fun `parses PLAN §3 sample`() {
        val text = """
        {
          "version": 1,
          "list_filter_enabled": true,
          "ssaid_rotation_enabled": true,
          "switch_hour": 12,
          "list_exempt": ["com.heytap.market", "com.android.vending"],
          "id_exempt": [],
          "visible_targets": ["mark.via"],
          "system_caller_deny": ["com.opos.ads"],
          "eco_whitelist_enabled": false,
          "eco_whitelist": ["com.tencent.mm"],
          "debug_bucket_offset": 0
        }
        """.trimIndent()

        val p = Policy.parse(text)

        assertTrue(p.listFilterEnabled)
        assertTrue(p.ssaidRotationEnabled)
        assertEquals(12, p.switchHour)
        assertEquals(setOf("com.heytap.market", "com.android.vending"), p.listExempt)
        assertTrue(p.idExempt.isEmpty())
        assertEquals(setOf("mark.via"), p.visibleTargets)
        assertEquals(setOf("com.opos.ads"), p.systemCallerDeny)
        assertFalse(p.ecoWhitelistEnabled)
        assertEquals(setOf("com.tencent.mm"), p.ecoWhitelist)
        assertEquals(0L, p.debugBucketOffset)
    }

    @Test
    fun `corrupt json falls back to built-in default (strict switches on)`() {
        for (bad in listOf("{not json", "", "   ", "[1,2,3]")) {
            val p = Policy.parse(bad)
            assertEquals(Policy.DEFAULT, p)
        }
        assertEquals(Policy.DEFAULT, Policy.parse(null))
    }

    @Test
    fun `built-in default keeps store and self exempt and denies opos`() {
        val d = Policy.DEFAULT

        assertTrue(d.listFilterEnabled)
        assertTrue(d.ssaidRotationEnabled)
        assertTrue("com.heytap.market" in d.listExempt)
        assertTrue("io.github.privacygate" in d.listExempt)
        assertEquals(setOf("com.opos.ads"), d.systemCallerDeny)
        assertFalse(d.ecoWhitelistEnabled)
        assertTrue(d.visibleTargets.isEmpty())
    }

    @Test
    fun `partial json overlays onto built-in default`() {
        val p = Policy.parse("""{"switch_hour": 0}""")

        // 缺省键沿用内置默认（缺失即最严，开关默认开）
        assertTrue(p.listFilterEnabled)
        assertTrue(p.ssaidRotationEnabled)
        assertEquals(0, p.switchHour)
        assertEquals(Policy.DEFAULT.listExempt, p.listExempt)
        assertEquals(Policy.DEFAULT.systemCallerDeny, p.systemCallerDeny)
    }

    @Test
    fun `explicit switches are respected`() {
        val p = Policy.parse(
            """{"list_filter_enabled": false, "ssaid_rotation_enabled": false,
                "eco_whitelist_enabled": true, "debug_bucket_offset": 3}"""
        )

        assertFalse(p.listFilterEnabled)
        assertFalse(p.ssaidRotationEnabled)
        assertTrue(p.ecoWhitelistEnabled)
        assertEquals(3L, p.debugBucketOffset)
    }

    @Test
    fun `invalid switch_hour falls back to 12`() {
        assertEquals(12, Policy.parse("""{"switch_hour": 25}""").switchHour)
        assertEquals(12, Policy.parse("""{"switch_hour": -3}""").switchHour)
    }

    @Test
    fun `blank entries in lists are dropped`() {
        val p = Policy.parse("""{"visible_targets": ["mark.via", "", "  "]}""")
        assertEquals(setOf("mark.via"), p.visibleTargets)
    }

    @Test
    fun `parseOrNull distinguishes corrupt from valid for hot reload`() {
        // 热加载语义：null → 保留上一份有效策略；非 null → 整体替换
        assertEquals(null, Policy.parseOrNull("{bad"))
        assertEquals(null, Policy.parseOrNull(null))
        assertEquals(null, Policy.parseOrNull(""))
        val ok = Policy.parseOrNull("{}")
        assertTrue(ok != null)
        assertTrue(ok!!.listFilterEnabled) // 合法 JSON 缺省键 → 内置默认（开关开）
    }

    @Test
    fun `cold load - corrupt or missing falls back to DEFAULT`() {
        assertEquals(Policy.DEFAULT, Policy.cold(null))
        assertEquals(Policy.DEFAULT, Policy.cold("{bad"))
        val p = Policy.cold("""{"switch_hour": 0}""")
        assertEquals(0, p.switchHour)
        assertTrue(p.listFilterEnabled)
    }

    @Test
    fun `hot load - corrupt or missing keeps previous policy`() {
        val prev = Policy.parse("""{"switch_hour": 6, "list_filter_enabled": false}""")
        assertEquals(prev, Policy.hot("{bad", prev))
        assertEquals(prev, Policy.hot(null, prev))
        assertEquals(prev, Policy.hot("", prev))
        val next = Policy.hot("""{"switch_hour": 12}""", prev)
        assertEquals(12, next.switchHour)
        assertTrue(next.listFilterEnabled)
    }
}
