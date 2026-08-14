package com.vpnproxy

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

data class ProxyConfig(
    val serverUrl: String = "https://185.68.246.229:443",
    val serverUrls: List<String> = emptyList(),
    val serverSelector: String = "round",
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
    val loggingLevel: String = "INFO",
) {
    fun effectiveServerUrls(): List<String> =
        if (serverUrls.isNotEmpty()) serverUrls else listOf(serverUrl)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("mode", "client")
            put("client", JSONObject().apply {
                put("socks5", JSONObject().apply {
                    put("bind_host", socksBindHost)
                    put("bind_port", socksBindPort)
                })
                put("server_url", serverUrl)
                put("server_urls", JSONArray().apply { effectiveServerUrls().forEach { put(it) } })
                put("server_selector", serverSelector)
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
                put("level", loggingLevel)
            })
        }
    }

    fun toPrettyJson(): String = toJson().toString(2).replace("\\/", "/")

    companion object {
        fun fromJson(obj: JSONObject): ProxyConfig {
            val defaults = ProxyConfig()
            val client = obj.optJSONObject("client") ?: JSONObject()
            val socks = client.optJSONObject("socks5") ?: JSONObject()
            val security = obj.optJSONObject("security") ?: JSONObject()
            val idleTimeout = client.optJSONObject("idle_timeout") ?: JSONObject()
            val dnsRelay = client.optJSONObject("dns_relay") ?: JSONObject()
            val logging = obj.optJSONObject("logging") ?: JSONObject()
            return ProxyConfig(
                serverUrl = client.optString("server_url", defaults.serverUrl),
                serverUrls = (client.optJSONArray("server_urls") ?: JSONArray()).let { arr ->
                    (0 until arr.length()).map { arr.getString(it).trim() }.filter { it.isNotEmpty() }
                },
                serverSelector = client.optString("server_selector", defaults.serverSelector),
                pollPath = client.optString("poll_path", defaults.pollPath),
                pollIntervalMs = client.optInt("poll_interval_ms", defaults.pollIntervalMs),
                pollJitterMs = client.optInt("poll_jitter_ms", defaults.pollJitterMs),
                maxChunkBytes = client.optInt("max_chunk_bytes", defaults.maxChunkBytes),
                verifyTls = client.optBoolean("verify_tls", defaults.verifyTls),
                pollMethod = client.optString("poll_method", defaults.pollMethod),
                pollDataIn = client.optString("poll_data_in", defaults.pollDataIn),
                hostHeader = client.optString("host_header", defaults.hostHeader),
                socksBindHost = socks.optString("bind_host", defaults.socksBindHost),
                socksBindPort = socks.optInt("bind_port", defaults.socksBindPort),
                psk = security.optString("psk", defaults.psk),
                hmacWindowSeconds = security.optInt("hmac_window_seconds", defaults.hmacWindowSeconds),
                idleTimeoutEnabled = idleTimeout.optBoolean("enabled", defaults.idleTimeoutEnabled),
                idleTimeoutSeconds = idleTimeout.optInt("seconds", defaults.idleTimeoutSeconds),
                dnsRelayEnabled = dnsRelay.optBoolean("enabled", defaults.dnsRelayEnabled),
                dnsBindHost = dnsRelay.optString("bind_host", defaults.dnsBindHost),
                dnsBindPort = dnsRelay.optInt("bind_port", defaults.dnsBindPort),
                loggingLevel = logging.optString("level", defaults.loggingLevel),
            )
        }
    }
}

data class AppRule(val packageName: String = "", val appName: String = "", val system: Boolean = false) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("package", packageName)
        put("name", appName)
    }

    companion object {
        fun fromJson(o: JSONObject): AppRule =
            AppRule(o.optString("package"), o.optString("name"))
    }
}

data class RoutingConfig(
    val mode: String = "all", // all | allow | block
    val allowedApps: List<AppRule> = emptyList(),
    val blockedApps: List<AppRule> = emptyList(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("mode", mode)
        put("allowed_apps", JSONArray().apply { allowedApps.forEach { put(it.toJson()) } })
        put("blocked_apps", JSONArray().apply { blockedApps.forEach { put(it.toJson()) } })
    }

    companion object {
        fun fromJson(o: JSONObject): RoutingConfig {
            val allow = (o.optJSONArray("allowed_apps") ?: JSONArray()).let { arr ->
                (0 until arr.length()).map { AppRule.fromJson(arr.getJSONObject(it)) }
            }
            val block = (o.optJSONArray("blocked_apps") ?: JSONArray()).let { arr ->
                (0 until arr.length()).map { AppRule.fromJson(arr.getJSONObject(it)) }
            }
            return RoutingConfig(o.optString("mode", "all"), allow, block)
        }
    }
}

data class VpnProfile(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "Default",
    val mode: String = "proxy", // proxy | vpn
    val config: ProxyConfig = ProxyConfig(),
    val routing: RoutingConfig = RoutingConfig(),
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("mode", mode)
        put("config", config.toJson())
        put("routing", routing.toJson())
    }

    companion object {
        fun fromJson(o: JSONObject): VpnProfile = VpnProfile(
            id = o.optString("id", UUID.randomUUID().toString()),
            name = o.optString("name", "Profile"),
            mode = o.optString("mode", "proxy"),
            config = ProxyConfig.fromJson(o.optJSONObject("config") ?: JSONObject()),
            routing = RoutingConfig.fromJson(o.optJSONObject("routing") ?: JSONObject()),
        )
    }
}

class ConfigManager(private val context: Context) {
    private val configFile = File(context.filesDir, "config.json")
    private val profilesFile = File(context.filesDir, "profiles.json")
    private val prefs = context.getSharedPreferences("vpnproxy", Context.MODE_PRIVATE)

    // ── Profiles ──────────────────────────────────────────────────────

    fun ensureProfiles(): List<VpnProfile> {
        if (!profilesFile.exists()) {
            val existing = if (configFile.exists()) parseRaw(configFile.readText()) else null
            val profile = VpnProfile(name = "Default", config = existing ?: ProxyConfig())
            saveProfiles(listOf(profile))
            prefs.edit().putString("active_profile", profile.id).apply()
            writeEngineConfig(profile)
            return listOf(profile)
        }
        return loadProfiles()
    }

    fun loadProfiles(): List<VpnProfile> {
        if (!profilesFile.exists()) return ensureProfiles()
        return try {
            val arr = JSONObject(profilesFile.readText()).getJSONArray("profiles")
            (0 until arr.length()).map { VpnProfile.fromJson(arr.getJSONObject(it)) }
        } catch (_: Exception) {
            ensureProfiles()
        }
    }

    fun saveProfiles(profiles: List<VpnProfile>) {
        val json = JSONObject().apply {
            put("active", prefs.getString("active_profile", profiles.firstOrNull()?.id ?: ""))
            put("profiles", JSONArray().apply { profiles.forEach { put(it.toJson()) } })
        }
        profilesFile.writeText(json.toString(2))
    }

    fun getActiveProfile(): VpnProfile {
        val profiles = loadProfiles()
        val activeId = prefs.getString("active_profile", null)
        return profiles.firstOrNull { it.id == activeId } ?: profiles.firstOrNull() ?: VpnProfile()
    }

    fun selectProfile(id: String) {
        prefs.edit().putString("active_profile", id).apply()
        getActiveProfile().let { writeEngineConfig(it) }
    }

    fun updateProfile(profile: VpnProfile) {
        val profiles = loadProfiles().toMutableList()
        val idx = profiles.indexOfFirst { it.id == profile.id }
        if (idx >= 0) profiles[idx] = profile else profiles.add(profile)
        saveProfiles(profiles)
        if (profile.id == getActiveProfile().id) writeEngineConfig(profile)
    }

    fun addProfile(profile: VpnProfile) {
        val profiles = loadProfiles().toMutableList()
        profiles.add(profile)
        saveProfiles(profiles)
    }

    fun deleteProfile(id: String) {
        val profiles = loadProfiles().toMutableList()
        if (profiles.size <= 1) return
        profiles.removeAll { it.id == id }
        if (prefs.getString("active_profile", null) == id) {
            prefs.edit().putString("active_profile", profiles.first().id).apply()
        }
        saveProfiles(profiles)
        getActiveProfile().let { writeEngineConfig(it) }
    }

    fun writeEngineConfig(profile: VpnProfile) {
        configFile.writeText(profile.config.toPrettyJson())
    }

    // ── Legacy API (Simple tab + service) ─────────────────────────────

    fun load(): ProxyConfig = getActiveProfile().config

    fun save(config: ProxyConfig) {
        val active = getActiveProfile()
        updateProfile(active.copy(config = config))
    }

    fun saveRaw(json: String) {
        configFile.writeText(json)
        parseRaw(json)?.let { parsed ->
            val active = getActiveProfile()
            updateProfile(active.copy(config = parsed))
        }
    }

    fun loadRaw(): String {
        if (!configFile.exists()) return ProxyConfig().toPrettyJson()
        return configFile.readText().replace("\\/", "/")
    }

    fun parseRaw(json: String): ProxyConfig? {
        return try {
            ProxyConfig.fromJson(JSONObject(json))
        } catch (_: Exception) {
            null
        }
    }
}
