package io.github.privacygate.core

/**
 * uid 数学（纯 JVM，可单测）。与 android.os.UserHandle / Process 的实现语义一致，
 * 放在纯函数层是为了让放行条件真值表可以脱离 Android 环境单测。
 */
object UidMath {

    const val PER_USER_RANGE = 100_000

    /** UserHandle.getAppId：uid 的低位段（appId = uid % PER_USER_RANGE） */
    fun appId(uid: Int): Int = uid % PER_USER_RANGE

    /** UserHandle.getUserId */
    fun userId(uid: Int): Int = uid / PER_USER_RANGE

    /** UserHandle.getUid */
    fun uidOf(userId: Int, appId: Int): Int = userId * PER_USER_RANGE + appId

    // Process.SDK_SANDBOX_FIRST_PROCESS_ID=40000, RANGE=10000
    private const val SDK_SANDBOX_FIRST = 40_000
    private const val SDK_SANDBOX_RANGE = 10_000

    /** Process.isSdkSandboxUid */
    fun isSdkSandboxUid(uid: Int): Boolean {
        val s = uid - userId(uid) * PER_USER_RANGE
        return s in SDK_SANDBOX_FIRST until (SDK_SANDBOX_FIRST + SDK_SANDBOX_RANGE)
    }
}
