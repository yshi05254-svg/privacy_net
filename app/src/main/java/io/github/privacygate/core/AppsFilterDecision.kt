package io.github.privacygate.core

/**
 * shouldFilterApplication after-hook 的决策核心（纯函数，JVM 单测）。
 *
 * 单调语义：只在原值为 false 时可能强制 true，绝不把 true 改成 false（PLAN §1.1）。
 * 返回 true = 强制过滤（覆盖原生结果）；false = 维持原生结果。
 *
 * callerKnown=false 表示 callingSetting 类型无法识别——按 fail-open 放行（不计入异常），
 * 避免误伤未知形态的系统调用方（audit.md §4）。
 */
object AppsFilterDecision {

    fun forceFilter(
        original: Boolean,
        killed: Boolean,
        listFilterEnabled: Boolean,
        callerAppId: Int,
        callerIsSdkSandbox: Boolean,
        callerKnown: Boolean,
        callerPkgNames: Set<String>,
        callerIsSystem: Boolean,
        targetAppId: Int,
        targetIsSystem: Boolean,
        targetPkgName: String,
        policy: Policy,
        implicitlyQueryable: Boolean,
    ): Boolean {
        if (original || killed || !listFilterEnabled) return false
        if (callerAppId < 10_000 || callerIsSdkSandbox) return false
        if (targetAppId < 10_000 || targetAppId == callerAppId) return false
        if (targetIsSystem) return false
        if (!callerKnown) return false
        // F1：系统调用方放行，但 system_caller_deny（如 com.opos.ads）除外
        if (callerIsSystem && callerPkgNames.none { it in policy.systemCallerDeny }) return false
        if (callerPkgNames.any { it in policy.listExempt }) return false
        if (targetPkgName in policy.visibleTargets) return false
        if (policy.ecoWhitelistEnabled && targetPkgName in policy.ecoWhitelist) return false
        if (implicitlyQueryable) return false
        return true
    }
}
