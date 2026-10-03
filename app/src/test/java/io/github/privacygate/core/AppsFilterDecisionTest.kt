package io.github.privacygate.core

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppsFilterDecisionTest {

    private fun policy(mut: (Policy) -> Policy = { it }): Policy = mut(Policy.DEFAULT)

    private fun decide(
        original: Boolean = false,
        killed: Boolean = false,
        listFilterEnabled: Boolean = true,
        callerAppId: Int = 10300,
        callerIsSdkSandbox: Boolean = false,
        callerKnown: Boolean = true,
        callerPkgNames: Set<String> = setOf("com.some.app"),
        callerIsSystem: Boolean = false,
        targetAppId: Int = 10100,
        targetIsSystem: Boolean = false,
        targetPkgName: String = "com.tencent.mm",
        policy: Policy = Policy.DEFAULT,
        implicitlyQueryable: Boolean = false,
    ): Boolean = AppsFilterDecision.forceFilter(
        original, killed, listFilterEnabled,
        callerAppId, callerIsSdkSandbox, callerKnown, callerPkgNames, callerIsSystem,
        targetAppId, targetIsSystem, targetPkgName, policy, implicitlyQueryable,
    )

    @Test
    fun `default third-party caller x third-party target forces filter`() {
        assertTrue(decide())
    }

    @Test
    fun `monotonic - original true never flipped to false`() {
        assertFalse(decide(original = true))
    }

    @Test
    fun `kill switch and master switch disable forcing`() {
        assertFalse(decide(killed = true))
        assertFalse(decide(listFilterEnabled = false))
    }

    @Test
    fun `system core callers pass (appId under 10000, sandbox)`() {
        assertFalse(decide(callerAppId = 1000))
        assertFalse(decide(callerAppId = 0))
        assertFalse(decide(callerIsSdkSandbox = true))
    }

    @Test
    fun `target passes when system or same app`() {
        assertFalse(decide(targetAppId = 1000))
        assertFalse(decide(targetAppId = 10300))
        assertFalse(decide(targetIsSystem = true))
    }

    @Test
    fun `unknown calling setting fails open`() {
        assertFalse(decide(callerKnown = false))
    }

    @Test
    fun `F1 - system caller passes unless in system_caller_deny`() {
        assertFalse(decide(callerIsSystem = true, callerPkgNames = setOf("com.android.launcher")))
        // com.opos.ads 在内置 deny 表里：即使是系统身份也强制过滤
        assertTrue(decide(callerIsSystem = true, callerPkgNames = setOf("com.opos.ads")))
    }

    @Test
    fun `list exempt caller passes`() {
        val p = policy { it.copy(listExempt = it.listExempt + "com.some.app") }
        assertFalse(decide(policy = p))
    }

    @Test
    fun `visible_targets target passes`() {
        val p = policy { it.copy(visibleTargets = setOf("com.tencent.mm")) }
        assertFalse(decide(policy = p))
    }

    @Test
    fun `eco whitelist only applies when enabled`() {
        val p = policy { it.copy(ecoWhitelistEnabled = true) }
        assertFalse(decide(policy = p))
        // 默认 ecoWhitelistEnabled=false：微信照样被过滤
        assertTrue(decide())
    }

    @Test
    fun `implicitly queryable passes (微信登录回调链路)`() {
        assertFalse(decide(implicitlyQueryable = true))
    }
}
