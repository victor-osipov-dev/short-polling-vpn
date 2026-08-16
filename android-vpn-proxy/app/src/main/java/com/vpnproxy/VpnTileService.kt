package com.vpnproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat

/**
 * Quick Settings tile для быстрого включения/выключения VPN (если активный
 * профиль в VPN-режиме) или прокси.
 *
 * Состояние тайла синхронизируется с фактическим состоянием через broadcast
 * STATE (source of truth): тайл сам слушает его и обновляет себя. При клике
 * тайл сразу показывает желаемое состояние, а сервис после реального старта/
 * остановки пришлёт STATE и скорректирует (в т.ч. при отзыве VPN системой).
 */
class VpnTileService : TileService() {

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ProxyService.ACTION_STATE) {
                setTileState(intent.getBooleanExtra("running", false))
            }
        }
    }
    private var receiverRegistered = false

    override fun onStartListening() {
        // Показываем актуальное состояние сервиса при открытии шторки.
        setTileState(ProxyService.isProxyRunning)
        if (!receiverRegistered) {
            // Слушаем STATE, чтобы тайл обновлялся по фактическому состоянию
            // (в т.ч. когда VPN отзывается системой или сервис стартует/останавливается).
            ContextCompat.registerReceiver(this, stateReceiver,
                IntentFilter(ProxyService.ACTION_STATE), ContextCompat.RECEIVER_NOT_EXPORTED)
            receiverRegistered = true
        }
    }

    override fun onStopListening() {
        if (receiverRegistered) {
            receiverRegistered = false
            try {
                unregisterReceiver(stateReceiver)
            } catch (_: Exception) {
            }
        }
        super.onStopListening()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (receiverRegistered) {
            receiverRegistered = false
            try {
                unregisterReceiver(stateReceiver)
            } catch (_: Exception) {
            }
        }
    }

    override fun onClick() {
        val running = ProxyService.isProxyRunning
        if (running) {
            stopProxy(this)
        } else {
            startProxy()
        }
        // Показываем желаемое состояние сразу; реальное состояние пришлёт STATE.
        setTileState(!running)
    }

    private fun startProxy() {
        val profile = ConfigManager(applicationContext).getActiveProfile()
        if (profile.mode == "vpn" && android.net.VpnService.prepare(this) != null) {
            // Согласие на VPN ещё не дано (или отозвано). Тайл не может открыть
            // Activity для запроса согласия, поэтому делегируем MainActivity,
            // которая запустит startProxyWithVpnCheck() и получит результат.
            sendBroadcast(Intent("com.vpnproxy.REQUEST_VPN_CONSENT").setPackage(packageName))
            return
        }
        startProxyInternal()
    }

    private fun startProxyInternal() {
        val intent = Intent(this, ProxyService::class.java).apply {
            action = ProxyService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun setTileState(running: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = getString(if (running) R.string.stop else R.string.start)
        tile.updateTile()
    }
}