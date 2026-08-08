package com.vpnproxy

import android.content.Context
import org.json.JSONObject
import java.io.File

data class ProxyConfig(
    val serverUrl: String = "https://185.68.246.229:443",
    val pollPath: String = "/poll",
    val pollIntervalMs: Int = 50,
    val pollJitterMs: Int = 5,
    val maxChunkBytes: Int = 65536,
    val verifyTls: Boolean = true,
    val pollMethod: String = "POST",
    val pollDataIn: String = "body",
    val hostHeader: String = "",
    val socksBindHost: String = "0.0.0.0",
    val socksBindPort: Int = 8888,
    val psk: String = "vTvesbK6BIh+ZPJf6pn4b+s7F+RvMi9ulrkFlPfX2qo=",
    val hmacWindowSeconds: Int = 30,
    val idleTimeoutEnabled: Boolean = false,
    val idleTimeoutSeconds: Int = 300,
    val dnsRelayEnabled: Boolean = false,
    val dnsBindHost: String = "127.0.0.1",
    val dnsBindPort: Int = 5353,
) {
    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("mode", "client")
            put("client", JSONObject().apply {
                put("socks5", JSONObject().apply {
                    put("bind_host", socksBindHost)
                    put("bind_port", socksBindPort)
                })
                put("server_url", serverUrl)
                put("poll_path", pollPath)
                put("poll_interval_ms", pollIntervalMs)
                put("poll_jitter_ms", pollJitterMs)
                put("max_chunk_bytes", maxChunkBytes)
                put("verify_tls", verifyTls)
                put("poll_method", pollMethod)
                put("poll_data_in", pollDataIn)
                put("host_header", hostHeader)
                put("idle_timeout", JSONObject().apply {
                    put("enabled", idleTimeoutEnabled)
                    put("seconds", idleTimeoutSeconds)
                })
                put("dns_relay", JSONObject().apply {
                    put("enabled", dnsRelayEnabled)
                    put("bind_host", dnsBindHost)
                    put("bind_port", dnsBindPort)
                })
            })
            put("security", JSONObject().apply {
                put("psk", psk)
                put("hmac_window_seconds", hmacWindowSeconds)
            })
            put("logging", JSONObject().apply {
                put("level", "INFO")
            })
        }
    }

    fun toPrettyJson(): String = toJson().toString(2).replace("\\/", "/")
}

class ConfigManager(private val context: Context) {
    private val configFile = File(context.filesDir, "config.json")

    fun load(): ProxyConfig {
        if (!configFile.exists()) return ProxyConfig()
        return try {
            val json = JSONObject(configFile.readText())
            val client = json.getJSONObject("client")
            val socks = client.getJSONObject("socks5")
            val security = json.getJSONObject("security")
            val idleTimeout = client.optJSONObject("idle_timeout") ?: JSONObject()
            val dnsRelay = client.optJSONObject("dns_relay") ?: JSONObject()
            ProxyConfig(
                serverUrl = client.optString("server_url", ProxyConfig().serverUrl),
                pollPath = client.optString("poll_path", ProxyConfig().pollPath),
                pollIntervalMs = client.optInt("poll_interval_ms", ProxyConfig().pollIntervalMs),
                pollJitterMs = client.optInt("poll_jitter_ms", ProxyConfig().pollJitterMs),
                maxChunkBytes = client.optInt("max_chunk_bytes", ProxyConfig().maxChunkBytes),
                verifyTls = client.optBoolean("verify_tls", ProxyConfig().verifyTls),
                pollMethod = client.optString("poll_method", ProxyConfig().pollMethod),
                pollDataIn = client.optString("poll_data_in", ProxyConfig().pollDataIn),
                hostHeader = client.optString("host_header", ""),
                socksBindHost = socks.optString("bind_host", ProxyConfig().socksBindHost),
                socksBindPort = socks.optInt("bind_port", ProxyConfig().socksBindPort),
                psk = security.optString("psk", ProxyConfig().psk),
                hmacWindowSeconds = security.optInt("hmac_window_seconds", ProxyConfig().hmacWindowSeconds),
                idleTimeoutEnabled = idleTimeout.optBoolean("enabled", false),
                idleTimeoutSeconds = idleTimeout.optInt("seconds", 300),
                dnsRelayEnabled = dnsRelay.optBoolean("enabled", false),
                dnsBindHost = dnsRelay.optString("bind_host", "127.0.0.1"),
                dnsBindPort = dnsRelay.optInt("bind_port", 5353),
            )
        } catch (_: Exception) {
            ProxyConfig()
        }
    }

    fun save(config: ProxyConfig) {
        configFile.writeText(config.toPrettyJson())
    }

    fun saveRaw(json: String) {
        configFile.writeText(json)
    }

    fun loadRaw(): String {
        if (!configFile.exists()) return ProxyConfig().toPrettyJson()
        return configFile.readText().replace("\\/", "/")
    }

    fun parseRaw(json: String): ProxyConfig? {
        return try {
            val obj = JSONObject(json)
            val client = obj.getJSONObject("client")
            val socks = client.getJSONObject("socks5")
            val security = obj.getJSONObject("security")
            val idleTimeout = client.optJSONObject("idle_timeout") ?: JSONObject()
            val dnsRelay = client.optJSONObject("dns_relay") ?: JSONObject()
            ProxyConfig(
                serverUrl = client.optString("server_url", ProxyConfig().serverUrl),
                pollPath = client.optString("poll_path", ProxyConfig().pollPath),
                pollIntervalMs = client.optInt("poll_interval_ms", ProxyConfig().pollIntervalMs),
                pollJitterMs = client.optInt("poll_jitter_ms", ProxyConfig().pollJitterMs),
                maxChunkBytes = client.optInt("max_chunk_bytes", ProxyConfig().maxChunkBytes),
                verifyTls = client.optBoolean("verify_tls", ProxyConfig().verifyTls),
                pollMethod = client.optString("poll_method", ProxyConfig().pollMethod),
                pollDataIn = client.optString("poll_data_in", ProxyConfig().pollDataIn),
                hostHeader = client.optString("host_header", ""),
                socksBindHost = socks.optString("bind_host", ProxyConfig().socksBindHost),
                socksBindPort = socks.optInt("bind_port", ProxyConfig().socksBindPort),
                psk = security.optString("psk", ProxyConfig().psk),
                hmacWindowSeconds = security.optInt("hmac_window_seconds", ProxyConfig().hmacWindowSeconds),
                idleTimeoutEnabled = idleTimeout.optBoolean("enabled", false),
                idleTimeoutSeconds = idleTimeout.optInt("seconds", 300),
                dnsRelayEnabled = dnsRelay.optBoolean("enabled", false),
                dnsBindHost = dnsRelay.optString("bind_host", "127.0.0.1"),
                dnsBindPort = dnsRelay.optInt("bind_port", 5353),
            )
        } catch (_: Exception) {
            null
        }
    }
}
