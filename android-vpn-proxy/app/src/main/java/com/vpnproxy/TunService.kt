package com.vpnproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.File
import java.io.FileOutputStream
import java.io.IOException

class TunService : VpnService() {

    companion object {
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 2
        const val ACTION_START = "com.vpnproxy.TUN_START"
        const val ACTION_STOP = "com.vpnproxy.TUN_STOP"
        const val VPN_ADDR = "10.8.0.2"
        const val VPN_MTU = 1500
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var handler: Handler? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        handler = Handler(Looper.getMainLooper())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?) = super.onBind(intent)

    private fun log(msg: String) {
        val intent = Intent("com.vpnproxy.LOG").apply {
            putExtra("msg", "[vpn] $msg")
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun startVpn() {
        if (vpnInterface != null) return
        val profile = ConfigManager(this).getActiveProfile()
        if (profile.mode != "vpn") {
            log("Active profile is not in VPN mode")
            stopSelf()
            return
        }

        val notification = buildNotification("Starting VPN...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_VPN)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val builder = Builder(this).apply {
            setSession("tun2socks")
            setMtu(VPN_MTU)
            addAddress(VPN_ADDR, 24)
            addRoute("0.0.0.0", 0)
            try {
                addRoute("::", 0)
            } catch (_: Exception) {
            }
            when (profile.routing.mode) {
                "allow" -> profile.routing.allowedApps.forEach { rule ->
                    try {
                        addAllowedApplication(rule.packageName)
                    } catch (_: Exception) {
                    }
                }
                "block" -> {
                    profile.routing.blockedApps.forEach { rule ->
                        try {
                            addDisallowedApplication(rule.packageName)
                        } catch (_: Exception) {
                        }
                    }
                    try {
                        addDisallowedApplication(packageName)
                    } catch (_: Exception) {
                    }
                }
                else -> try {
                    addDisallowedApplication(packageName)
                } catch (_: Exception) {
                }
            }
        }

        val pfd = builder.establish()
        if (pfd == null) {
            log("Establish failed (permission revoked?)")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        vpnInterface = pfd

        val bin = extractBinary()
        if (bin == null) {
            log("No tun2socks binary for ABI " + Build.SUPPORTED_ABIS.firstOrNull())
            pfd.close()
            vpnInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        val fd = pfd.fd
        val argv = arrayOf(
            bin.absolutePath,
            "-d", "fd://$fd",
            "-p", "socks5://127.0.0.1:${profile.config.socksBindPort}",
            "--mtu", VPN_MTU.toString(),
            "--loglevel", "info"
        )
        val logFile = File(filesDir, "tun2socks.log")

        TunRunner.launch(fd, argv, logFile.absolutePath) { code ->
            log("tun2socks exited: $code")
            handler?.post {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        log("VPN established on $VPN_ADDR, socks→127.0.0.1:${profile.config.socksBindPort}")
        updateNotification("VPN running")
    }

    private fun stopVpn() {
        TunRunner.stop()
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        }
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    private fun extractBinary(): File? {
        val abi = Build.SUPPORTED_ABIS.firstOrNull { it == "arm64-v8a" } ?: return null
        val dest = File(filesDir, "tun2socks")
        try {
            assets.open("bin/$abi/tun2socks").use { input ->
                FileOutputStream(dest).use { output -> input.copyTo(output) }
            }
            dest.setExecutable(true, true)
            dest.setReadable(true, true)
            return dest
        } catch (e: IOException) {
            log("Binary extract failed: ${e.message}")
            return null
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.vpn_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = getString(R.string.vpn_channel_desc) }
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
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }
}