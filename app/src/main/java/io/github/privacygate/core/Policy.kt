package io.github.privacygate.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * 不可变策略（PLAN §3）。热加载时整体替换引用，热路径只读字段。
 *
 * 内置默认值（DEFAULT）用于文件缺失或损坏时（F10）：保护全开、保留商店与模块自身的
 * 必要豁免；急停 disable 文件是唯一的全局关闭方式。
 * JSON 里显式给出的键覆盖默认值；缺省键沿用默认值（因此同样满足"缺失即最严"）。
 */
data class Policy(
    val listFilterEnabled: Boolean,
    val ssaidRotationEnabled: Boolean,
    val switchHour: Int,
    val listExempt: Set<String>,
    val idExempt: Set<String>,
    val visibleTargets: Set<String>,
    val systemCallerDeny: Set<String>,
    val ecoWhitelistEnabled: Boolean,
    val ecoWhitelist: Set<String>,
    val debugBucketOffset: Long,
) {
    companion object {

        /** 内置默认：解析失败/文件缺失时使用 */
        val DEFAULT = Policy(
            listFilterEnabled = true,
            ssaidRotationEnabled = true,
            switchHour = DayBucket.DEFAULT_SWITCH_HOUR,
            listExempt = setOf(
                "com.heytap.market",
                "com.android.vending",
                "io.github.privacygate",
            ),
            idExempt = emptySet(),
            visibleTargets = emptySet(),
            systemCallerDeny = setOf("com.opos.ads"),
            ecoWhitelistEnabled = false,
            ecoWhitelist = setOf(
                "com.tencent.mm",
                "com.tencent.mobileqq",
                "com.eg.android.AlipayGphone",
            ),
            debugBucketOffset = 0L,
        )

        /**
         * 解析失败返回 null（文件损坏/缺失），供 PolicyStore 区分三种状态：
         * 冷启动 null → 用 DEFAULT；热加载 null → 保留上一份有效策略；非 null → 整体替换。
         */
        fun parseOrNull(text: String?): Policy? {
            if (text.isNullOrBlank()) return null
            return try {
                fromJson(JSONObject(text))
            } catch (_: Throwable) {
                null
            }
        }

        fun parse(text: String?): Policy = parseOrNull(text) ?: DEFAULT

        /** 冷启动：缺失/损坏 → DEFAULT */
        fun cold(text: String?): Policy = parseOrNull(text) ?: DEFAULT

        /** 热加载：缺失/损坏 → 保留上一份有效策略 */
        fun hot(text: String?, prev: Policy): Policy = parseOrNull(text) ?: prev

        private fun fromJson(o: JSONObject): Policy {
            val hour = o.optInt("switch_hour", DEFAULT.switchHour)
            return Policy(
                listFilterEnabled = o.optBoolean("list_filter_enabled", DEFAULT.listFilterEnabled),
                ssaidRotationEnabled = o.optBoolean("ssaid_rotation_enabled", DEFAULT.ssaidRotationEnabled),
                switchHour = if (hour in 0..23) hour else DayBucket.DEFAULT_SWITCH_HOUR,
                listExempt = o.optStringSet("list_exempt", DEFAULT.listExempt),
                idExempt = o.optStringSet("id_exempt", DEFAULT.idExempt),
                visibleTargets = o.optStringSet("visible_targets", DEFAULT.visibleTargets),
                systemCallerDeny = o.optStringSet("system_caller_deny", DEFAULT.systemCallerDeny),
                ecoWhitelistEnabled = o.optBoolean("eco_whitelist_enabled", DEFAULT.ecoWhitelistEnabled),
                ecoWhitelist = o.optStringSet("eco_whitelist", DEFAULT.ecoWhitelist),
                debugBucketOffset = o.optLong("debug_bucket_offset", DEFAULT.debugBucketOffset),
            )
        }

        private fun JSONObject.optStringSet(name: String, fallback: Set<String>): Set<String> {
            val arr: JSONArray = optJSONArray(name) ?: return fallback
            val out = LinkedHashSet<String>(arr.length())
            for (i in 0 until arr.length()) {
                val s = arr.optString(i, "")
                if (s.isNotBlank()) out.add(s.trim())
            }
            return out
        }
    }
}
