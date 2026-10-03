package io.github.privacygate.hook

import io.github.libxposed.api.XposedInterface
import io.github.privacygate.core.AppsFilterDecision
import io.github.privacygate.core.PolicyStore
import io.github.privacygate.core.UidMath

/**
 * 第一（唯一必需）防线：AppsFilterBase.shouldFilterApplication after-hook（PLAN §1.1）。
 *
 * 覆盖：getInstalled*、queryIntent*、resolve*、LauncherApps、按 uid 查询、显式组件解析、
 * 包广播（getVisibilityAllowList 内部同点）。单调：只把 false 强制成 true。
 *
 * 反射缓存：目标包信息走 PackageState 接口三方法（audit.md §2-a）；callingSetting 支持
 * PackageStateInternal（单包）与 SharedUserSetting（sharedUid 成员包名，audit.md §2-b）；
 * isImplicitlyQueryable / isRetainedImplicitlyQueryable 经 thisObject 调用（完整 uid，F6）。
 * 未知 callingSetting 形态 → fail-open 放行并计数（audit.md §4）。
 */
object AppsFilterHooks {

    private const val APPS_FILTER = "com.android.server.pm.AppsFilterBase"
    private const val PKG_STATE = "com.android.server.pm.pkg.PackageState"
    private const val SHARED_USER = "com.android.server.pm.SharedUserSetting"

    // 反射缓存（install 时解析一次，热路径只 invoke）
    private var pkgStateClass: Class<*>? = null
    private var sharedUserClass: Class<*>? = null
    private var getPackageNameM: java.lang.reflect.Method? = null
    private var isSystemM: java.lang.reflect.Method? = null
    private var getAppIdM: java.lang.reflect.Method? = null
    private var getPackagesM: java.lang.reflect.Method? = null
    private var isImplicitM: java.lang.reflect.Method? = null
    private var isRetainedImplicitM: java.lang.reflect.Method? = null

    fun install(xposed: XposedInterface, cl: ClassLoader, store: PolicyStore) {
        try {
            val af = cl.loadClass(APPS_FILTER)

            val target = af.declaredMethods.firstOrNull { m ->
                m.name == "shouldFilterApplication" &&
                    m.parameterCount == 5 &&
                    m.parameterTypes[0].name.endsWith("PackageDataSnapshot") &&
                    m.parameterTypes[1] == Int::class.javaPrimitiveType &&
                    m.parameterTypes[2] == Any::class.java &&
                    m.parameterTypes[3].name.endsWith("PackageStateInternal") &&
                    m.parameterTypes[4] == Int::class.javaPrimitiveType &&
                    m.returnType == Boolean::class.javaPrimitiveType
            } ?: throw NoSuchMethodException("$APPS_FILTER.shouldFilterApplication(5-arg) not found")
            target.isAccessible = true

            isImplicitM = declaredTwoIntBool(af, "isImplicitlyQueryable")
            isRetainedImplicitM = declaredTwoIntBool(af, "isRetainedImplicitlyQueryable")

            val state = cl.loadClass(PKG_STATE)
            pkgStateClass = state
            getPackageNameM = state.methods.firstOrNull { it.name == "getPackageName" && it.parameterCount == 0 }
            isSystemM = state.methods.firstOrNull { it.name == "isSystem" && it.parameterCount == 0 }
            getAppIdM = state.methods.firstOrNull { it.name == "getAppId" && it.parameterCount == 0 }

            val shared = cl.loadClass(SHARED_USER)
            sharedUserClass = shared
            getPackagesM = shared.methods.firstOrNull { it.name == "getPackages" && it.parameterCount == 0 }

            xposed.hook(target)
                .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                .intercept { chain -> decide(chain, store) }

            store.appsfilterInstalled = true
        } catch (t: Throwable) {
            store.noteError("appsfilter_install", t)
        }
    }

    private fun declaredTwoIntBool(cls: Class<*>, name: String): java.lang.reflect.Method? =
        cls.declaredMethods.firstOrNull {
            it.name == name && it.parameterCount == 2 &&
                it.parameterTypes[0] == Int::class.javaPrimitiveType &&
                it.parameterTypes[1] == Int::class.javaPrimitiveType &&
                it.returnType == Boolean::class.javaPrimitiveType
        }?.apply { isAccessible = true }

    private fun decide(chain: XposedInterface.Chain, store: PolicyStore): Any? {
        val res = (chain.proceed() as? Boolean) ?: true
        val p = store.current()
        if (res || store.isKilled() || !p.listFilterEnabled) return res

        try {
            val callingUid = chain.getArg(1) as Int
            val callerAppId = UidMath.appId(callingUid)
            if (callerAppId < 10_000 || UidMath.isSdkSandboxUid(callingUid)) return res

            val target = chain.getArg(3)
            val state = pkgStateClass
            if (target == null || state == null || !state.isInstance(target)) {
                return unknownCallingSetting(store, res)
            }
            val userId = chain.getArg(4) as Int
            val targetAppId = (getAppIdM?.invoke(target) as? Int)
                ?: return unknownCallingSetting(store, res)
            val targetIsSystem = (isSystemM?.invoke(target) as? Boolean)
                ?: return unknownCallingSetting(store, res)
            val targetName = getPackageNameM?.invoke(target) as? String
                ?: return unknownCallingSetting(store, res)

            val caller = callerInfo(chain.getArg(2)) ?: return unknownCallingSetting(store, res)

            val tUid = UidMath.uidOf(userId, targetAppId)
            val implicit = runCatching {
                (isImplicitM?.invoke(chain.thisObject, callingUid, tUid) as? Boolean) == true ||
                    (isRetainedImplicitM?.invoke(chain.thisObject, callingUid, tUid) as? Boolean) == true
            }.getOrDefault(false)

            val forced = AppsFilterDecision.forceFilter(
                original = res,
                killed = store.isKilled(),
                listFilterEnabled = p.listFilterEnabled,
                callerAppId = callerAppId,
                callerIsSdkSandbox = false, // 前面已排除
                callerKnown = true,
                callerPkgNames = caller.names,
                callerIsSystem = caller.isSystem,
                targetAppId = targetAppId,
                targetIsSystem = targetIsSystem,
                targetPkgName = targetName,
                policy = p,
                implicitlyQueryable = implicit,
            )
            if (forced) store.noteFirstHit()
            return forced
        } catch (t: Throwable) {
            store.noteError("appsfilter_intercept", t)
            return res
        }
    }

    private class CallerInfo(val names: Set<String>, val isSystem: Boolean)

    /** callingSetting → (成员包名集合, 是否系统)。形态未知返回 null（fail-open） */
    private fun callerInfo(setting: Any?): CallerInfo? {
        if (setting == null) return null
        return try {
            val shared = sharedUserClass
            if (shared != null && shared.isInstance(setting)) {
                val list = getPackagesM?.invoke(setting) as? List<*> ?: return null
                val names = HashSet<String>(list.size)
                var sys = false
                for (member in list) {
                    if (member == null) continue
                    (getPackageNameM?.invoke(member) as? String)?.let { names.add(it) }
                    if ((isSystemM?.invoke(member) as? Boolean) == true) sys = true
                }
                CallerInfo(names, sys)
            } else {
                val state = pkgStateClass
                if (state == null || !state.isInstance(setting)) return null
                val name = getPackageNameM?.invoke(setting) as? String ?: return null
                val sys = (isSystemM?.invoke(setting) as? Boolean) ?: return null
                CallerInfo(setOf(name), sys)
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun unknownCallingSetting(store: PolicyStore, res: Any?): Any? {
        store.noteError("unknown_calling_setting", IllegalStateException("unrecognized type"))
        return res
    }
}
