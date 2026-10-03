package io.github.privacygate.hook

import io.github.libxposed.api.XposedModule
import io.github.libxposed.api.XposedModuleInterface.PackageLoadedParam
import io.github.libxposed.api.XposedModuleInterface.SystemServerStartingParam
import io.github.privacygate.core.PolicyStore

/**
 * PrivacyGate 模块入口（libxposed API 101，Vector v2.2 加载，作用域=system）。
 *
 * onSystemServerStarting：
 *   1. PolicyStore.init() —— 冷加载策略、急停状态、密钥文件、FileObserver 热加载；
 *   2. AppsFilterHooks.install —— shouldFilterApplication after-hook（PLAN §1.1）；
 *   3. status.json 记录安装结果。
 * onPackageLoaded（(e) 项已实测会回调 SettingsProvider，见 docs/audit.md §2）：
 *   阶段 4 在此挂载 SsidHooks（getSsaidSettingLocked + packageValueForCallResult）。
 *
 * 可观测性：/data/system/privacygate/status.json（logcat 缓冲会冲掉启动期日志，不可靠）。
 */
class PgModule : XposedModule() {

    override fun onSystemServerStarting(param: SystemServerStartingParam) {
        val store = PolicyStore
        store.init()
        AppsFilterHooks.install(this, param.classLoader, store)
        store.writeStatus("system_server_starting")
    }

    override fun onPackageLoaded(param: PackageLoadedParam) {
        if (param.packageName == "com.android.providers.settings") {
            PolicyStore.ssaidHostSeen = true
            // 阶段 4：SsidHooks.install(this, param.defaultClassLoader, PolicyStore)
            PolicyStore.writeStatus("ssaid_host_loaded")
        }
    }
}
