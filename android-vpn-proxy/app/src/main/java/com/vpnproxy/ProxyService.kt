package com.vpnproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.BitmapFactory
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
        const val ACTION_URL_STATUS = "com.vpnproxy.URL_STATUS"
        const val ACTION_RESET_URL_ERRORS = "com.vpnproxy.RESET_URL_ERRORS"

        // Разделяемое состояние: позволяет UI прочитать фактическое состояние
        // сервиса при запуске Activity (если сервис уже работает после рестарта процесса).
        @Volatile
        var isProxyRunning = false
    }

    private var pythonThread: Thread? = null
    private var statusThread: Thread? = null
    @Volatile
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
            ACTION_RESET_URL_ERRORS -> {
                log("Service received RESET_URL_ERRORS action")
                resetUrlErrors()
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
        startStatusPoller()

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
        statusThread?.interrupt()
        statusThread = null
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

    /** Периодически отправляет UI снимок состояния URL (карантин/ошибки). */
    private fun startStatusPoller() {
        if (statusThread?.isAlive == true) return
        statusThread = Thread({
            while (pythonStarted) {
                broadcastUrlStatus()
                try {
                    Thread.sleep(1500)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }, "url-status").also { it.start() }
    }

    private fun broadcastUrlStatus() {
        if (!pythonStarted || !Python.isStarted()) return
        try {
            val json = Python.getInstance()
                .getModule("proxy_engine")
                .callAttr("get_url_status")
                ?.toString() ?: "[]"
            sendBroadcast(Intent(ACTION_URL_STATUS).apply {
                putExtra("status", json)
                setPackage(packageName)
            })
        } catch (_: Exception) {
        }
    }

    private fun resetUrlErrors() {
        if (!pythonStarted || !Python.isStarted()) return
        try {
            Python.getInstance()
                .getModule("proxy_engine")
                .callAttr("reset_url_status")
            broadcastUrlStatus()
        } catch (_: Exception) {
        }
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
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentIntent = PendingIntent.getActivity(
            this, 0, launchIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setLargeIcon(BitmapFactory.decodeResource(resources, R.mipmap.ic_launcher))
            .setContentIntent(contentIntent)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
