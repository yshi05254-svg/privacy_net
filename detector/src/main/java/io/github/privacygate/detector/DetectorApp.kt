package io.github.privacygate.detector

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build

/**
 * 进程级 PACKAGE_ADDED/REPLACED/REMOVED 监听（L8）。
 * 在 Application.onCreate 注册，进程存活期间持续收集事件到静态 sink；
 * 报告的 l8_events 字段为当时快照。
 */
class DetectorApp : Application() {

    companion object {
        val events: MutableList<String> = java.util.Collections.synchronizedList(mutableListOf())
    }

    override fun onCreate() {
        super.onCreate()
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addAction(Intent.ACTION_PACKAGE_REMOVED)
            addDataScheme("package")
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val pkg = intent.data?.schemeSpecificPart ?: "?"
                events.add("${intent.action} pkg=$pkg @${System.currentTimeMillis()}")
            }
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(receiver, filter)
        }
    }
}
