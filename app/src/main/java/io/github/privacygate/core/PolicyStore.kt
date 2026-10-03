package io.github.privacygate.core

import android.os.FileObserver
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * 策略与控制面（system_server 内，PLAN §1.3）。
 *
 * - 冷启动：policy.json 缺失/损坏 → DEFAULT（开关全开、保留内置豁免）；
 * - 热加载：解析失败 → 保留上一份有效策略（Policy.parseOrNull 语义）；
 * - /data/system/privacygate/disable 存在 = 急停，所有 hook 直通（热路径 AtomicBoolean 零 IO）；
 * - FileObserver 监听 policy.json / disable 的 CREATE|CLOSE_WRITE|MOVED_TO|DELETE，事件驱动热加载；
 * - status.json 只在事件时写（初始化、重载、首次命中、异常节流 1/min）；
 * - 热加载替换后调 PackageManager.invalidatePackageInfoCache()（F11）。
 */
object PolicyStore {

    const val DIR = "/data/system/privacygate"
    private const val POLICY = "policy.json"
    private const val DISABLE = "disable"
    private const val KEY = "key"
    private const val STATUS = "status.json"
    private const val ERROR_THROTTLE_MS = 60_000L

    @Volatile
    var policy: Policy = Policy.DEFAULT
        private set

    @Volatile
    var killed: Boolean = false
        private set

    @Volatile
    var appsfilterInstalled: Boolean = false

    @Volatile
    var ssaidInstalled: Boolean = false

    @Volatile
    var ssaidHostSeen: Boolean = false

    private val initialized = AtomicBoolean(false)
    private val firstHit = AtomicLong(0)
    private val lastErrorWrite = AtomicLong(0)
    private val errorCount = AtomicLong(0)
    private var observer: FileObserver? = null
    private var lastPolicyError: String? = null
    private val writeLock = Any()

    fun init() {
        if (!initialized.compareAndSet(false, true)) return
        try {
            val dir = File(DIR)
            if (!dir.isDirectory) dir.mkdirs()
            makePrivate(dir)
            ensureKeyFile()
            policy = Policy.cold(readPolicyText())
            killed = File(DIR, DISABLE).exists()
            startObserver()
            writeStatus("init")
        } catch (t: Throwable) {
            noteError("init", t)
        }
    }

    fun current(): Policy = policy

    /** 热路径：急停判定（零 IO） */
    fun isKilled(): Boolean = killed

    private fun readPolicyText(): String? =
        try {
            File(DIR, POLICY).readText()
        } catch (_: Throwable) {
            null
        }

    private fun startObserver() {
        val mask = FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or
            FileObserver.CREATE or FileObserver.DELETE
        observer = object : FileObserver(DIR, mask) {
            override fun onEvent(event: Int, path: String?) {
                if (path == POLICY || path == DISABLE) reload()
            }
        }.also { it.startWatching() }
    }

    /** 观察线程执行；IO 允许。解析失败保留旧策略（PLAN §1.3） */
    fun reload() {
        try {
            val prev = policy
            killed = File(DIR, DISABLE).exists()
            policy = Policy.hot(readPolicyText(), prev)
            if (policy !== prev) invalidatePackageInfoCache()
            writeStatus("reload")
        } catch (t: Throwable) {
            noteError("reload", t)
        }
    }

    /** 首次实际强制过滤时记录（热路径只做一次 AtomicLong CAS） */
    fun noteFirstHit() {
        if (firstHit.compareAndSet(0, System.currentTimeMillis())) writeStatus("first_hit")
    }

    fun noteError(where: String, t: Throwable) {
        errorCount.incrementAndGet()
        val now = System.currentTimeMillis()
        val prev = lastErrorWrite.get()
        if (now - prev >= ERROR_THROTTLE_MS && lastErrorWrite.compareAndSet(prev, now)) {
            writeStatus("error:$where:${t.javaClass.simpleName}")
        }
    }

    fun writeStatus(reason: String) {
        try {
            synchronized(writeLock) {
                val o = JSONObject()
                    .put("ts", System.currentTimeMillis())
                    .put("reason", reason)
                    .put("appsfilter_hook", appsfilterInstalled)
                    .put("ssaid_hook", ssaidInstalled)
                    .put("ssaid_host_seen", ssaidHostSeen)
                    .put("killed", killed)
                    .put("first_hit", if (firstHit.get() == 0L) JSONObject.NULL else firstHit.get())
                    .put("errors", errorCount.get())
                    .put("policy_error", lastPolicyError ?: JSONObject.NULL)
                    .put("switch_hour", policy.switchHour)
                    .put("list_filter_enabled", policy.listFilterEnabled)
                    .put("ssaid_rotation_enabled", policy.ssaidRotationEnabled)
                val tmp = File(DIR, "$STATUS.tmp")
                tmp.writeText(o.toString(2))
                if (!tmp.renameTo(File(DIR, STATUS))) tmp.delete()
            }
        } catch (_: Throwable) {
        }
    }

    /** 阶段 4 使用：读取或首次生成 32 字节密钥（0600）。失败返回 null，调用方按禁用轮换处理 */
    fun ensureKeyFile(): ByteArray? {
        return try {
            val f = File(DIR, KEY)
            if (f.isFile && f.length() >= 32L) {
                f.readBytes()
            } else {
                val bytes = ByteArray(32)
                SecureRandom().nextBytes(bytes)
                f.writeBytes(bytes)
                makePrivate(f)
                bytes
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun makePrivate(f: File) {
        f.setReadable(false, false)
        f.setReadable(true, true)
        f.setWritable(false, false)
        f.setWritable(true, true)
        f.setExecutable(false, false)
        f.setExecutable(true, true) // 目录需 x；文件 0700/0600 的 x 位对常规文件无副作用
    }

    private fun invalidatePackageInfoCache() {
        try {
            Class.forName("android.content.pm.PackageManager")
                .getMethod("invalidatePackageInfoCache")
                .invoke(null)
        } catch (_: Throwable) {
        }
    }
}
