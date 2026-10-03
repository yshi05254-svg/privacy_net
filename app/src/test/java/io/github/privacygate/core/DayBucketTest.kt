package io.github.privacygate.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.TimeZone

class DayBucketTest {

    private val tz = TimeZone.getTimeZone("Asia/Shanghai")

    private fun ms(
        y: Int, mo: Int, d: Int, h: Int, mi: Int, s: Int,
        zone: ZoneId = ZoneId.of("Asia/Shanghai"),
    ): Long = ZonedDateTime.of(y, mo, d, h, mi, s, 0, zone).toInstant().toEpochMilli()

    @Test
    fun `switch at noon - bucket increments exactly at 12_00 local`() {
        val before = DayBucket.bucket(ms(2026, 9, 27, 11, 59, 59), 12, tz)
        val at = DayBucket.bucket(ms(2026, 9, 27, 12, 0, 0), 12, tz)
        val after = DayBucket.bucket(ms(2026, 9, 27, 12, 0, 1), 12, tz)

        assertEquals(before + 1, at)
        assertEquals(at, after)
    }

    @Test
    fun `noon boundary - whole window from day D noon to day D+1 noon shares one bucket`() {
        val noonD = DayBucket.bucket(ms(2026, 9, 27, 12, 0, 0), 12, tz)
        val lateNightD = DayBucket.bucket(ms(2026, 9, 27, 23, 59, 59), 12, tz)
        val earlyMorningD1 = DayBucket.bucket(ms(2026, 9, 28, 0, 0, 0), 12, tz)
        val beforeNoonD1 = DayBucket.bucket(ms(2026, 9, 28, 11, 59, 59), 12, tz)

        assertEquals(noonD, lateNightD)
        assertEquals(noonD, earlyMorningD1)
        assertEquals(noonD, beforeNoonD1)
    }

    @Test
    fun `switch at midnight - bucket increments exactly at 00_00 local`() {
        val before = DayBucket.bucket(ms(2026, 9, 27, 23, 59, 59), 0, tz)
        val at = DayBucket.bucket(ms(2026, 9, 28, 0, 0, 0), 0, tz)

        assertEquals(before + 1, at)
    }

    @Test
    fun `timezone is honored - same utc instant can land in different buckets`() {
        val t = ms(2026, 9, 27, 20, 0, 0, ZoneId.of("UTC")) // 上海已是 9/28 04:00

        val utcBucket = DayBucket.bucket(t, 0, TimeZone.getTimeZone("UTC"))
        val shBucket = DayBucket.bucket(t, 0, tz)

        assertNotEquals(utcBucket, shBucket)
    }

    @Test
    fun `invalid switch hour falls back to 12`() {
        val t = ms(2026, 9, 27, 12, 0, 0)
        assertEquals(DayBucket.bucket(t, 12, tz), DayBucket.bucket(t, 25, tz))
        assertEquals(DayBucket.bucket(t, 12, tz), DayBucket.bucket(t, -1, tz))
    }

    @Test
    fun `bucket is stable within the same minute and monotonic over days`() {
        val d1 = DayBucket.bucket(ms(2026, 9, 27, 13, 0, 0), 12, tz)
        val d2 = DayBucket.bucket(ms(2026, 9, 28, 13, 0, 0), 12, tz)
        val d3 = DayBucket.bucket(ms(2026, 9, 29, 13, 0, 0), 12, tz)

        assertEquals(d1 + 1, d2)
        assertEquals(d2 + 1, d3)
    }
}
