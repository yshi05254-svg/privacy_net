package io.github.privacygate.detector

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.LauncherApps
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Process
import android.provider.Settings
import android.view.inputmethod.InputMethodManager
import com.heytap.openid.IOpenID
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * 探测项实现（PLAN §4-阶段2）。全部结果为原始观测值，不做对错判断；
 * 期望对比在 docs/verify-log.md 里做。
 *
 * I2：绑定 com.heytap.openid/.IdentifyService（OUID 服务端）。queries flavor 的
 * manifest 需包含 <package android:name="com.heytap.openid"/> 才能绑定。
 */
object Suites {

    private const val TAG = "PGDetect"

    private fun isSystem(ai: ApplicationInfo?): Boolean =
        ai != null && (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0

    private var l10comps: Array<String>? = null

    fun runAll(ctx: Context, comps: Array<String>?): JSONObject {
        l10comps = comps
        val out = JSONObject()
        out.put("flavor", BuildConfig.FLAVOR)
        out.put("pkg", ctx.packageName)
        out.put("ts", System.currentTimeMillis())
        for ((id, fn) in items()) {
            val t0 = System.currentTimeMillis()
            try {
                out.put(id, fn(ctx))
            } catch (t: Throwable) {
                out.put(id, JSONObject().put("error", "${t.javaClass.simpleName}: ${t.message ?: ""}"))
            }
            out.put("${id}_ms", System.currentTimeMillis() - t0)
        }
        out.put("l8_events", JSONArray(DetectorApp.events.toList()))
        return out
    }

    private fun items(): List<Pair<String, (Context) -> Any>> = listOf(
        "L1_getInstalledPackages" to ::l1,
        "L2_getInstalledApplications" to ::l2,
        "L3_queryLauncher" to ::l3,
        "L4_probePackages" to ::l4,
        "L5_scanUids" to ::l5,
        "L6_launcherApps" to ::l6,
        "L7_servicesProviders" to ::l7,
        "L9_resolveHttp" to ::l9,
        "L10_startUnexported" to ::l10,
        "L11_secureKeys" to ::l11,
        "L12_immsAccessibility" to ::l12,
        "I1_androidId" to ::i1,
        "I2_heytapOpenId" to ::i2,
    )

    /** L1: getInstalledPackages(0) */
    private fun l1(ctx: Context): Any {
        val pkgs = ctx.packageManager.getInstalledPackages(0).map { it.packageName }
        return JSONObject()
            .put("count", pkgs.size)
            .put("names", JSONArray(pkgs.sorted()))
    }

    /** L2: getInstalledApplications(0)，带系统/第三方分类 */
    private fun l2(ctx: Context): Any {
        val apps = ctx.packageManager.getInstalledApplications(0)
        val third = apps.filter { !isSystem(it) }.map { it.packageName }.sorted()
        return JSONObject()
            .put("count", apps.size)
            .put("third_party_count", third.size)
            .put("third_party", JSONArray(third))
    }

    /** L3: queryIntentActivities(MAIN/LAUNCHER) */
    private fun l3(ctx: Context): Any {
        val pm = ctx.packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val pkgs = pm.queryIntentActivities(intent, 0)
            .mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .sorted()
        val third = pkgs.filter { p -> runCatching { !isSystem(pm.getApplicationInfo(p, 0)) }.getOrDefault(true) }
        return JSONObject()
            .put("count", pkgs.size)
            .put("third_party", JSONArray(third))
            .put("names", JSONArray(pkgs))
    }

    /** L4: 定点 getPackageInfo 探测 */
    private fun l4(ctx: Context): Any {
        val pm = ctx.packageManager
        val targets = listOf(
            "com.tencent.mm", "com.xunmeng.pinduoduo", "tv.danmaku.bili", "mark.via",
            "com.sohu.inputmethod.sogou", "io.github.privacygate",
            "io.github.privacygate.detector.full", "io.github.privacygate.detector.queries",
            "io.github.privacygate.dummy", "org.matrix.vector.rootguard",
            "org.matrix.roothider.manager", "com.opos.ads", "com.heytap.market",
            "com.android.vending", "com.jingdong.app.mall", "com.heytap.openid",
        )
        val visible = targets.filter { runCatching { pm.getPackageInfo(it, 0) }.isSuccess }
        return JSONObject()
            .put("targets", JSONArray(targets))
            .put("visible", JSONArray(visible))
    }

    /** L5: getPackagesForUid/getNameForUid 扫描（user 0 与分身 999） */
    private fun l5(ctx: Context): Any {
        val pm = ctx.packageManager
        fun scan(range: IntRange): JSONObject {
            val found = JSONArray()
            var probed = 0
            for (uid in range) {
                probed++
                val pkgs = pm.getPackagesForUid(uid) ?: continue
                if (pkgs.isEmpty()) continue
                found.put(JSONObject().put("uid", uid).put("pkgs", JSONArray(pkgs.toList())))
            }
            return JSONObject().put("probed", probed).put("uids_with_pkgs", found)
        }
        val u0 = scan(10000..10999)
        val u999 = scan(99910000..99910999)
        // 分类：把返回包里非系统的（含无法取 ApplicationInfo 的）标为潜在第三方
        fun countThird(o: JSONObject): Int {
            var n = 0
            val arr = o.getJSONArray("uids_with_pkgs")
            for (i in 0 until arr.length()) {
                val pkgs = arr.getJSONObject(i).getJSONArray("pkgs")
                for (j in 0 until pkgs.length()) {
                    val isSys = runCatching { isSystem(pm.getApplicationInfo(pkgs.getString(j), 0)) }
                        .getOrDefault(false)
                    if (!isSys) n++
                }
            }
            return n
        }
        return JSONObject()
            .put("user0", u0)
            .put("user999", u999)
            .put("user0_potential_third_party_pkgs", countThird(u0))
            .put("user999_potential_third_party_pkgs", countThird(u999))
            .put("self_uid", Process.myUid())
            .put("self_name", pm.getNameForUid(Process.myUid()))
    }

    /** L6: LauncherApps.getActivityList(null, myUser) */
    private fun l6(ctx: Context): Any {
        val la = ctx.getSystemService(LauncherApps::class.java)
            ?: return JSONObject().put("error", "LauncherApps unavailable")
        val list = la.getActivityList(null, Process.myUserHandle())
        val pkgs = list.map { it.componentName.packageName }.distinct().sorted()
        val pm = ctx.packageManager
        val third = pkgs.filter { p -> runCatching { !isSystem(pm.getApplicationInfo(p, 0)) }.getOrDefault(true) }
        return JSONObject()
            .put("count", pkgs.size)
            .put("third_party", JSONArray(third))
            .put("names", JSONArray(pkgs))
    }

    /** L7: queryIntentServices(定点) + queryContentProviders + resolveContentProvider(已知 authority) */
    private fun l7(ctx: Context): Any {
        val pm = ctx.packageManager
        val mmServices = runCatching {
            pm.queryIntentServices(Intent().setPackage("com.tencent.mm"), 0).mapNotNull { it.serviceInfo?.name }
        }.getOrDefault(emptyList())
        val providers = runCatching {
            @Suppress("DEPRECATION")
            pm.queryContentProviders(null, 0, 0).mapNotNull { it.packageName }
        }.getOrDefault(emptyList())
        val authorities = listOf("settings", "media", "call_log", "com.android.providers.contacts", "user_dictionary")
        val resolved = JSONObject()
        for (a in authorities) {
            val ri = runCatching { pm.resolveContentProvider(a, 0) }.getOrNull()
            resolved.put(a, ri?.packageName ?: JSONObject.NULL)
        }
        return JSONObject()
            .put("mm_services_count", mmServices.size)
            .put("provider_pkgs", JSONArray(providers.distinct().sorted()))
            .put("resolve_authorities", resolved)
    }

    /** L9: resolveActivity(VIEW http) */
    private fun l9(ctx: Context): Any {
        val ri = ctx.packageManager.resolveActivity(
            Intent(Intent.ACTION_VIEW, Uri.parse("http://www.example.com")), 0
        )
        return JSONObject()
            .put("package", ri?.activityInfo?.packageName ?: JSONObject.NULL)
            .put("activity", ri?.activityInfo?.name ?: JSONObject.NULL)
    }

    /** L10: startActivity 显式组件，记录异常类型（comps 来自 am --esa 传入：pkg/cls;pkg/cls） */
    private fun l10(ctx: Context): Any {
        val comps = l10comps ?: return JSONObject().put("skipped", "no comps extra")
        val arr = JSONArray()
        for (c in comps) {
            val parts = c.split("/", limit = 2)
            if (parts.size != 2) continue
            val entry = JSONObject().put("component", c)
            try {
                ctx.startActivity(
                    Intent(Intent.ACTION_MAIN)
                        .setClassName(parts[0], parts[1])
                        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
                entry.put("result", "LAUNCHED")
            } catch (e: ActivityNotFoundException) {
                entry.put("result", "ActivityNotFoundException")
            } catch (e: SecurityException) {
                entry.put("result", "SecurityException")
                entry.put("detail", (e.message ?: "").take(120))
            } catch (t: Throwable) {
                entry.put("result", "other:${t.javaClass.simpleName}")
            }
            arr.put(entry)
        }
        return JSONObject().put("tried", arr)
    }

    /** L11: Settings.Secure 中含包名的键（逐键容错：A16 对 targetSdk>33 的部分键直接抛 SecurityException） */
    private fun l11(ctx: Context): Any {
        val keys = listOf(
            "default_input_method", "enabled_input_methods",
            "enabled_accessibility_services", "autofill_service",
            "voice_interaction_service", "selected_spell_checker_service",
        )
        val o = JSONObject()
        val cr = ctx.contentResolver
        for (k in keys) {
            try {
                o.put(k, Settings.Secure.getString(cr, k) ?: JSONObject.NULL)
            } catch (t: Throwable) {
                o.put(k, "SECURITY_EXCEPTION(${t.message?.take(100)})")
            }
        }
        return o
    }

    /** L12: IMM 列表 + 无障碍服务列表 */
    private fun l12(ctx: Context): Any {
        val imm = ctx.getSystemService(InputMethodManager::class.java)
        val imms = runCatching { imm.getInputMethodList() }.getOrDefault(emptyList())
            .map { it.packageName }.distinct().sorted()
        val am = android.view.accessibility.AccessibilityManager::class.java
            .let { ctx.getSystemService(it) }
        val installed = runCatching {
            am.getInstalledAccessibilityServiceList()
                .map { it.resolveInfo.serviceInfo.packageName }.distinct().sorted()
        }.getOrDefault(emptyList())
        val enabled = runCatching {
            am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .map { it.resolveInfo.serviceInfo.packageName }.distinct().sorted()
        }.getOrDefault(emptyList())
        return JSONObject()
            .put("input_methods", JSONArray(imms))
            .put("a11y_installed", JSONArray(installed))
            .put("a11y_enabled", JSONArray(enabled))
    }

    /** I1: android_id 三条读取路径的一致性 */
    private fun i1(ctx: Context): Any {
        val cr = ctx.contentResolver
        val direct1 = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)
        val direct2 = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID)
        var byQuery: String? = null
        runCatching {
            cr.query(
                Settings.Secure.CONTENT_URI, arrayOf("value"), "name=?",
                arrayOf(Settings.Secure.ANDROID_ID), null
            )?.use { c -> if (c.moveToFirst()) byQuery = c.getString(0) }
        }
        var rowCount = -1
        var fromFullTable: String? = null
        runCatching {
            cr.query(Settings.Secure.CONTENT_URI, null, null, null, null)?.use { c ->
                val nameIdx = c.getColumnIndex("name")
                val valIdx = c.getColumnIndex("value")
                rowCount = c.count
                while (c.moveToNext()) {
                    if (c.getString(nameIdx) == Settings.Secure.ANDROID_ID) fromFullTable = c.getString(valIdx)
                }
            }
        }
        return JSONObject()
            .put("direct1", direct1 ?: JSONObject.NULL)
            .put("direct2", direct2 ?: JSONObject.NULL)
            .put("by_row_query", byQuery ?: JSONObject.NULL)
            .put("from_full_table", fromFullTable ?: JSONObject.NULL)
            .put("full_table_rows", rowCount)
            .put(
                "consistent",
                direct1 == direct2 && direct2 == byQuery && byQuery == fromFullTable
            )
    }

    /** I2: 绑定 HeyTap OpenID 服务读 OUID */
    private fun i2(ctx: Context): Any {
        val app = ctx.applicationContext
        val latch = CountDownLatch(1)
        val result = JSONObject()
        var done = false
        val conn = object : android.content.ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: android.os.IBinder?) {
                try {
                    val s = IOpenID.Stub.asInterface(binder)
                    val v = s.getSerID(app.packageName, "PrivacyGateProbe", "1")
                    result.put("bound", true).put("ouid", v ?: JSONObject.NULL)
                } catch (t: Throwable) {
                    result.put("bound", true).put("call_error", "${t.javaClass.simpleName}: ${t.message ?: ""}")
                }
                done = true
                latch.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) {}
        }
        val intent = Intent("action.com.heytap.openid.OPEN_ID_SERVICE")
            .setClassName("com.heytap.openid", "com.heytap.openid.IdentifyService")
        val bound = try {
            app.bindService(intent, conn, Context.BIND_AUTO_CREATE)
        } catch (t: Throwable) {
            result.put("bind_error", "${t.javaClass.simpleName}: ${t.message ?: ""}")
            false
        }
        if (bound) {
            latch.await(4, TimeUnit.SECONDS)
            if (!done) result.put("timeout", true)
            runCatching { app.unbindService(conn) }
        } else if (!result.has("bind_error")) {
            result.put("bound", false)
        }
        return result
    }
}
