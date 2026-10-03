package io.github.privacygate.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UidMathTest {

    @Test
    fun `appId and userId round trip`() {
        assertEquals(10429, UidMath.appId(10429))          // 主用户普通应用
        assertEquals(0, UidMath.userId(10429))
        assertEquals(10003, UidMath.appId(99910003))       // 分身用户
        assertEquals(999, UidMath.userId(99910003))
        assertEquals(99910003, UidMath.uidOf(999, 10003))
        assertEquals(10429, UidMath.uidOf(0, 10429))
        assertEquals(1000, UidMath.appId(1000))            // system
        assertEquals(2000, UidMath.appId(2000))            // shell
    }

    @Test
    fun `sdk sandbox uid range`() {
        assertTrue(UidMath.isSdkSandboxUid(40000))
        assertTrue(UidMath.isSdkSandboxUid(44999))
        assertFalse(UidMath.isSdkSandboxUid(39999))
        assertFalse(UidMath.isSdkSandboxUid(10429))
    }
}
