package io.github.privacygate.detector

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import io.github.privacygate.detector.BuildConfig
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 探测器入口。
 * 触发：`am start -n io.github.privacygate.detector.<flavor>/.Main --es run all [--esa comps pkg/cls;...]`
 * 输出：logcat(PGDetect) REPORT_FILE/PART 分块（base64），同时写 getExternalFilesDir/report-<ts>.json。
 * 采集脚本：tools/verify/collect_report.py
 */
class Main : Activity() {

    private lateinit var tv: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tv = TextView(this).apply {
            setPadding(48, 48, 48, 48)
            text = "PGDetector ${BuildConfig.FLAVOR} ready\npkg=$packageName\n"
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(tv)
        })
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val mode = intent.getStringExtra("run") ?: "all"
        val comps = intent.getStringArrayExtra("comps")
        tv.append("run=$mode comps=${comps?.size ?: 0}\n")
        if (mode != "all") return
        Thread {
            val report = try {
                Suites.runAll(applicationContext, comps)
            } catch (t: Throwable) {
                JSONObject().put("fatal", "${t.javaClass.simpleName}: ${t.message}")
            }
            emit(report)
            runOnUiThread { tv.append("report emitted\n") }
        }.start()
    }

    private fun emit(json: JSONObject) {
        val runId = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val pretty = json.toString(2)
        // 内部目录：run-as 可靠可读（主采集通道）；外部目录：方便人工取用
        val internal = File(filesDir, "report-$runId.json")
        runCatching { internal.writeText(pretty) }
        val extDir = getExternalFilesDir(null)
        var extPath = "n/a"
        if (extDir != null) {
            val f = File(extDir, "report-$runId.json")
            runCatching { f.writeText(pretty) }
            extPath = f.absolutePath
        }
        Log.i(TAG, "REPORT_FILE internal=$internal external=$extPath")
        Log.i(TAG, "BEGIN $runId")
        Base64.encodeToString(json.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
            .chunked(2400)
            .forEachIndexed { i, p -> Log.i(TAG, "PART $runId ${i + 1} $p") }
        Log.i(TAG, "END $runId")
    }

    companion object {
        const val TAG = "PGDetect"
    }
}
