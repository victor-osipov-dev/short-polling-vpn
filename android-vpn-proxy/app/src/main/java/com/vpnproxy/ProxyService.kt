package com.vpnproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

fun interface PyCallback {
    fun call(msg: Any?)
}

class ProxyService : Service() {

    companion object {
        const val CHANNEL_ID = "proxy_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.vpnproxy.START"
        const val ACTION_STOP = "com.vpnproxy.STOP"
        const val ACTION_STATE = "com.vpnproxy.STATE"

        // Разделяемое состояние: позволяет UI прочитать фактическое состояние
        // сервиса при запуске Activity (если сервис уже работает после рестарта процесса).
        @Volatile
        var isProxyRunning = false
    }

    private var pythonThread: Thread? = null
    private var pythonStarted = false

    private fun log(msg: String) {
        val intent = Intent("com.vpnproxy.LOG").apply {
            putExtra("msg", msg)
            setPackage(packageName) // Гарантируем доставку внутри приложения
        }
        sendBroadcast(intent)
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    private fun broadcastState(running: Boolean) {
        isProxyRunning = running
        sendBroadcast(Intent(ACTION_STATE).apply {
            action = ACTION_STATE
            putExtra("running", running)
            setPackage(packageName)
        })
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                log("Service received START action")
                startProxy()
            }
            ACTION_STOP -> {
                log("Service received STOP action")
                stopProxy()
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startProxy() {
        if (pythonStarted) {
            log("Proxy already running")
            return
        }

        val notification = buildNotification("Starting proxy...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        log("Initializing Python...")
        if (!Python.isStarted()) {
            try {
                Python.start(AndroidPlatform(this))
                log("Python initialized successfully")
            } catch (e: Exception) {
                log("Python initialization failed: ${e.message}")
                return
            }
        }

        val configPath = ConfigManager(this).let { mgr ->
            mgr.save(mgr.load())
            "${filesDir.absolutePath}/config.json"
        }

        pythonStarted = true
        pythonThread = Thread({
            try {
                log("Starting Python engine...")
                val py = Python.getInstance()
                val module = py.getModule("proxy_engine")
                module.callAttr("start", configPath, PyCallback { msg ->
                    log(msg.toString())
                })
                log("Python engine 'start' called")
            } catch (e: Exception) {
                log("Python Engine Error: ${e.message}")
            }
        }, "python-proxy").also { it.start() }

        updateNotification("Proxy running")
        broadcastState(true)

        if (ConfigManager(this).getActiveProfile().mode == "vpn") {
            log("Mode is VPN, starting TunService")
            startTunService()
        }
    }

    private fun startTunService() {
        val intent = Intent(this, TunService::class.java).apply {
            action = TunService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopTunService() {
        try {
            val intent = Intent(this, TunService::class.java).apply {
                action = TunService.ACTION_STOP
            }
            startService(intent)
        } catch (_: Exception) {
        }
    }

    private fun stopProxy() {
        stopTunService()
        pythonStarted = false
        if (Python.isStarted()) {
            try {
                val py = Python.getInstance()
                val module = py.getModule("proxy_engine")
                module.callAttr("stop")
            } catch (_: Exception) {}
        }
        pythonThread?.interrupt()
        pythonThread = null
        broadcastState(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = getString(R.string.channel_desc) }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
