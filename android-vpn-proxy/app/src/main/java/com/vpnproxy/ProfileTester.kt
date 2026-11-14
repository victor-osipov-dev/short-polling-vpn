package com.vpnproxy

import android.content.Context
import androidx.compose.runtime.mutableStateMapOf
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Результат проверки подключения одного профиля. */
data class ProfileTestResult(
    val running: Boolean = false,
    val ok: Boolean? = null,
    val latencyMs: Long = 0,
    val exitIp: String = "",
    val route: String = "",
    val error: String = "",
)

/**
 * Проверка подключения профилей без запуска основного VPN-сервиса.
 *
 * Для каждого профиля Python-движок поднимает временный туннель, открывает
 * реальную сессию через выбранный маршрут и запрашивает exit IP. Тесты
 * выполняются последовательно, чтобы не конкурировать за CPU/сеть.
 */
object ProfileTester {
    val results = mutableStateMapOf<String, ProfileTestResult>()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()

    @Volatile
    private var busy = false

    fun isBusy(): Boolean = busy

    /** Проверяет один профиль или сразу список (например, всю подписку). */
    fun test(context: Context, profiles: List<VpnProfile>) {
        if (profiles.isEmpty()) return
        val appContext = context.applicationContext
        scope.launch {
            mutex.withLock {
                busy = true
                try {
                    for (profile in profiles) testOne(appContext, profile)
                } finally {
                    busy = false
                }
            }
        }
    }

    private suspend fun testOne(context: Context, profile: VpnProfile) {
        withContext(Dispatchers.Main) {
            results[profile.id] = ProfileTestResult(running = true)
        }
        val result = try {
            val py = ensurePython(context)
            val configJson = TestConfig.build(profile.config)
            val raw = py.getModule("proxy_engine")
                .callAttr("test_profile", configJson, 15.0)
                .toString()
            val obj = JSONObject(raw)
            ProfileTestResult(
                running = false,
                ok = obj.optBoolean("ok", false),
                latencyMs = obj.optLong("latency_ms", 0L),
                exitIp = obj.optString("exit_ip", ""),
                route = obj.optString("route", ""),
                error = obj.optString("error", ""),
            )
        } catch (e: Throwable) {
            ProfileTestResult(
                running = false,
                ok = false,
                error = (e.message ?: e.javaClass.simpleName),
            )
        }
        withContext(Dispatchers.Main) {
            results[profile.id] = result
        }
    }

    @Synchronized
    private fun ensurePython(context: Context): Python {
        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(context))
        }
        return Python.getInstance()
    }

    fun clear() {
        results.clear()
    }
}

/** Готовит конфиг профиля для временного проверочного туннеля. */
internal object TestConfig {
    fun build(cfg: ProxyConfig): String {
        val json = JSONObject(cfg.toJson().toString())

        // У профиля уже есть снимок nodes/routes из подписки — не ходим
        // в сеть повторно. Старые профили без снимка пусть обновятся.
        val nodes = json.optJSONArray("nodes")
        if (nodes != null && nodes.length() > 0) {
            json.remove("subscription")
        }

        // Локальные действия профиля важнее действий из подписки:
        // проверяем именно то, что выбрал пользователь.
        val actions = JSONObject()
        fun putAction(key: String, value: String) {
            if (value.isBlank()) return
            if (value.equals("direct", ignoreCase = true)) {
                actions.put(key, JSONObject().put("direct", true))
            } else {
                actions.put(key, JSONObject().put("route", value))
            }
        }
        putAction("ru", cfg.routeRu)
        putAction("non_ru", cfg.routeNonRu)
        putAction("private", cfg.routePrivate)
        json.put("split_routing", JSONObject().apply {
            put("enabled", cfg.routingEnabled)
            put("default", "non_ru")
            put("actions", actions)
        })

        // Проверка должна быть быстрой: обычные интервалы опроса не нужны.
        json.optJSONObject("client")?.let { client ->
            client.put("poll_interval_ms", minOf(client.optInt("poll_interval_ms", 100), 100))
            client.put("poll_jitter_ms", minOf(client.optInt("poll_jitter_ms", 5), 10))
            client.optJSONObject("idle_timeout")?.put("enabled", false)
            client.optJSONObject("dns_relay")?.put("enabled", false)
        }
        return json.toString()
    }
}
