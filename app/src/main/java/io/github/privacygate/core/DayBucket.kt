package io.github.privacygate.core

import java.util.TimeZone

/**
 * 日期桶：HMAC 派生输入里的"天数"，驱动每日轮换。
 *
 * PLAN §1.2：bucket = floor((nowUtcMs + tz.getOffset(nowUtcMs) - switchHour*3_600_000) / 86_400_000)
 * switchHour = 12（中午 12:00 切换，默认）或 0（午夜切换）。
 * debug_bucket_offset（在 Policy 中）由调用方加在返回值上，用于模拟跨天，不进入本函数。
 *
 * 纯 JVM 逻辑，不依赖 Android API。
 */
object DayBucket {

    const val DAY_MS: Long = 86_400_000L
    const val HOUR_MS: Long = 3_600_000L

    /** switchHour 的合法范围；越界按默认 12 处理 */
    const val DEFAULT_SWITCH_HOUR: Int = 12

    fun bucket(nowUtcMs: Long, switchHour: Int, tz: TimeZone = TimeZone.getDefault()): Long {
        val hour = if (switchHour in 0..23) switchHour else DEFAULT_SWITCH_HOUR
        val localMs = nowUtcMs + tz.getOffset(nowUtcMs)
        return Math.floorDiv(localMs - hour * HOUR_MS, DAY_MS)
    }
}
