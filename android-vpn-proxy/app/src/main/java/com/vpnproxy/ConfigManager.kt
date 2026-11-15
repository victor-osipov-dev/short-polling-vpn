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
    val pollIntervalMs: Int = 100,
    val pollJitterMs: Int = 10,
    val padPolls: Boolean = true,
    val maxChunkBytes: Int = 65536,
    val verifyTls: Boolean = true,
    val pollMethod: String = "POST",
    val pollDataIn: String = "body",
    val hostHeader: String = "",
    val urlFailLimit: Int = 3,
    val urlCooldownSeconds: Int = 60,
    val disabledUrls: List<String> = emptyList(),
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
    val userId: String = "",
    val userSecret: String = "",
    val deviceId: String = "",
    val subscriptionUrl: String = "",
    val subscriptionFile: String = "",
    val subscriptionName: String = "",
    val routingEnabled: Boolean = false,
    val routeRu: String = "",
    val routeNonRu: String = "",
    val routePrivate: String = "direct",
    val routingOptions: String = "",
    // JSON-массивы из подписки: узлы и каталог маршрутов конструктора.
    // Нужны Python-движку, чтобы имя маршрута превращалось в цепочку URL.
    val nodesJson: String = "",
    val routesJson: String = "",
) {
    fun effectiveServerUrls(): List<String> =
        if (serverUrls.isNotEmpty()) serverUrls else listOf(serverUrl)

    fun toJson(): JSONObject {
        return JSONObject().apply {
            put("mode", "client")
            if (subscriptionUrl.isNotBlank() || subscriptionFile.isNotBlank() || subscriptionName.isNotBlank()) {
                put("subscription", JSONObject().apply {
                    put("url", subscriptionUrl)
                    put("file", subscriptionFile)
                    put("name", subscriptionName)
                })
            }
            if (userId.isNotBlank() || userSecret.isNotBlank() || deviceId.isNotBlank()) {
                put("user", JSONObject().apply {
                    put("uuid", userId)
                    put("secret", userSecret)
                    put("device_id", deviceId)
                })
            }
            put("routing", JSONObject().apply {
                put("enabled", routingEnabled)
                put("ru", routeRu)
                put("non_ru", routeNonRu)
                put("private", routePrivate)
            })
            if (routingOptions.isNotBlank()) put("routing_options", routingOptions)
            if (nodesJson.isNotBlank()) {
                runCatching { put("nodes", JSONArray(nodesJson)) }
            }
            if (routesJson.isNotBlank()) {
                runCatching { put("routes", JSONArray(routesJson)) }
            }
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
                put("pad_polls", padPolls)
                put("max_chunk_bytes", maxChunkBytes)
                put("verify_tls", verifyTls)
                put("poll_method", pollMethod)
                put("poll_data_in", pollDataIn)
                put("host_header", hostHeader)
                put("url_fail_limit", urlFailLimit)
                put("url_cooldown_seconds", urlCooldownSeconds)
                put("disabled_urls", JSONArray().apply {
                    disabledUrls.forEach { put(it) }
                })
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
            val user = obj.optJSONObject("user") ?: JSONObject()
            val subscription = obj.optJSONObject("subscription") ?: JSONObject()
            val routing = obj.optJSONObject("routing") ?: JSONObject()
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
                padPolls = client.optBoolean("pad_polls", defaults.padPolls),
                maxChunkBytes = client.optInt("max_chunk_bytes", defaults.maxChunkBytes),
                verifyTls = client.optBoolean("verify_tls", defaults.verifyTls),
                pollMethod = client.optString("poll_method", defaults.pollMethod),
                pollDataIn = client.optString("poll_data_in", defaults.pollDataIn),
                hostHeader = client.optString("host_header", defaults.hostHeader),
                urlFailLimit = client.optInt("url_fail_limit", defaults.urlFailLimit),
                urlCooldownSeconds = client.optInt("url_cooldown_seconds", defaults.urlCooldownSeconds),
                disabledUrls = (client.optJSONArray("disabled_urls") ?: JSONArray()).let { arr ->
                    (0 until arr.length()).map { arr.getString(it).trim() }.filter { it.isNotEmpty() }
                },
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
                userId = user.optString("uuid", defaults.userId),
                userSecret = user.optString("secret", defaults.userSecret),
                deviceId = user.optString("device_id", defaults.deviceId),
                subscriptionUrl = subscription.optString("url", defaults.subscriptionUrl),
                subscriptionFile = subscription.optString("file", defaults.subscriptionFile),
                subscriptionName = subscription.optString("name", defaults.subscriptionName),
                routingEnabled = routing.optBoolean("enabled", defaults.routingEnabled),
                routeRu = routing.optString("ru", defaults.routeRu),
                routeNonRu = routing.optString("non_ru", defaults.routeNonRu),
                routePrivate = routing.optString("private", defaults.routePrivate),
                routingOptions = obj.optString("routing_options", defaults.routingOptions),
                nodesJson = obj.optJSONArray("nodes")?.toString() ?: defaults.nodesJson,
                routesJson = obj.optJSONArray("routes")?.toString() ?: defaults.routesJson,
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

data class ClientProfileDef(
    val id: String = "",
    val name: String = "",
    val mode: String = "proxy",
    val enabled: Boolean = true,
    val splitEnabled: Boolean = false,
    val routeRu: String = "",
    val routeNonRu: String = "",
    val routePrivate: String = "direct",
    val sortOrder: Int = 0,
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("id", id)
        put("name", name)
        put("mode", mode)
        put("enabled", enabled)
        put("split_enabled", splitEnabled)
        put("route_ru", routeRu)
        put("route_non_ru", routeNonRu)
        put("route_private", routePrivate)
        put("sort_order", sortOrder)
    }

    companion object {
        fun fromJson(o: JSONObject): ClientProfileDef = ClientProfileDef(
            id = o.optString("id", ""),
            name = o.optString("name", "Profile"),
            mode = o.optString("mode", "proxy"),
            enabled = o.optBoolean("enabled", true),
            splitEnabled = o.optBoolean("split_enabled", false),
            routeRu = o.optString("route_ru", ""),
            routeNonRu = o.optString("route_non_ru", ""),
            routePrivate = o.optString("route_private", "direct"),
            sortOrder = o.optInt("sort_order", 0),
        )
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
            // По умолчанию — ноль профилей. Пользователь добавляет подписку
            // или создаёт профиль сам.
            saveProfiles(emptyList())
            prefs.edit().remove("active_profile").apply()
            return emptyList()
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

    fun getActiveProfile(): VpnProfile? {
        val profiles = loadProfiles()
        val activeId = prefs.getString("active_profile", null)
        return profiles.firstOrNull { it.id == activeId } ?: profiles.firstOrNull()
    }

    fun selectProfile(id: String) {
        prefs.edit().putString("active_profile", id).apply()
        getActiveProfile()?.let { writeEngineConfig(it) }
    }

    /** Все профили, пришедшие из подписки (для редактора в приложении). */
    fun loadClientProfiles(): List<ClientProfileDef> {
        val raw = prefs.getString("client_profiles", "") ?: ""
        if (raw.isBlank()) return emptyList()
        return try {
            val arr = JSONArray(raw)
            (0 until arr.length()).map { ClientProfileDef.fromJson(arr.getJSONObject(it)) }
                .sortedBy { it.sortOrder }
        } catch (_: Exception) {
            emptyList()
        }
    }

    fun saveClientProfiles(profiles: List<ClientProfileDef>) {
        prefs.edit().putString(
            "client_profiles",
            JSONArray().apply { profiles.forEach { put(it.toJson()) } }.toString()
        ).apply()
        applyClientProfiles(profiles)
    }

    /** Применяет именованные профили подписки к локальным профилям приложения. */
    fun applyClientProfiles(profiles: List<ClientProfileDef>) {
        if (profiles.isEmpty()) return
        val base = getActiveProfile()?.config ?: ProxyConfig()
        for (cp in profiles) {
            if (!cp.enabled) continue
            val localId = "sub:" + cp.id
            val existing = loadProfiles().firstOrNull { it.id == localId }
            val updated = (existing?.config ?: base).copy(
                routingEnabled = cp.splitEnabled,
                routeRu = cp.routeRu.ifBlank { (existing?.config ?: base).routeRu },
                routeNonRu = cp.routeNonRu.ifBlank { (existing?.config ?: base).routeNonRu },
                routePrivate = cp.routePrivate.ifBlank { "direct" },
                subscriptionName = (existing?.config ?: base).subscriptionName,
                subscriptionUrl = (existing?.config ?: base).subscriptionUrl,
                userId = (existing?.config ?: base).userId,
                userSecret = (existing?.config ?: base).userSecret,
                deviceId = (existing?.config ?: base).deviceId,
                serverUrl = (existing?.config ?: base).serverUrl,
                serverUrls = (existing?.config ?: base).serverUrls,
                nodesJson = (existing?.config ?: base).nodesJson,
                routesJson = (existing?.config ?: base).routesJson,
            )
            val profile = VpnProfile(
                id = localId,
                name = cp.name,
                mode = cp.mode,
                config = updated,
                routing = existing?.routing ?: RoutingConfig(),
            )
            if (existing != null) updateProfile(profile) else addProfile(profile)
        }
        getActiveProfile()?.let { writeEngineConfig(it) }
    }

    fun updateProfile(profile: VpnProfile) {
        val profiles = loadProfiles().toMutableList()
        val idx = profiles.indexOfFirst { it.id == profile.id }
        if (idx >= 0) profiles[idx] = profile else profiles.add(profile)
        saveProfiles(profiles)
        if (profile.id == getActiveProfile()?.id) writeEngineConfig(profile)
    }

    fun addProfile(profile: VpnProfile) {
        val profiles = loadProfiles().toMutableList()
        profiles.add(profile)
        saveProfiles(profiles)
    }

    fun deleteProfile(id: String) {
        val profiles = loadProfiles().toMutableList()
        profiles.removeAll { it.id == id }
        if (prefs.getString("active_profile", null) == id) {
            prefs.edit().putString("active_profile", profiles.firstOrNull()?.id ?: "").apply()
        }
        saveProfiles(profiles)
        profiles.firstOrNull()?.let { writeEngineConfig(it) }
    }

    fun writeEngineConfig(profile: VpnProfile) {
        configFile.writeText(profile.config.toPrettyJson())
    }

    /** Нормализованный ключ подписки: URL без завершающего слеша. */
    fun normalizeSubscriptionUrl(url: String): String = url.trim().trimEnd('/')

    /**
     * Стабильный короткий идентификатор подписки. Нужен, чтобы профили
     * разных подписок не сталкивались по id, даже если панель раздаёт
     * одинаковые id именованных профилей во всех подписках.
     */
    private fun subscriptionSlug(url: String, uuid: String): String {
        val key = when {
            url.isNotBlank() -> "url:" + normalizeSubscriptionUrl(url)
            uuid.isNotBlank() -> "user:$uuid"
            else -> "subscription"
        }
        return UUID.nameUUIDFromBytes(key.toByteArray()).toString().take(8)
    }

    /** Все профили, принадлежащие подписке с указанным URL. */
    fun profilesOfSubscription(url: String): List<VpnProfile> {
        val key = normalizeSubscriptionUrl(url)
        if (key.isBlank()) return emptyList()
        return loadProfiles().filter {
            normalizeSubscriptionUrl(it.config.subscriptionUrl) == key
        }
    }

    /**
     * Удаляет только профили одной подписки. Другие подписки и локальные
     * профили не затрагиваются.
     */
    fun deleteSubscription(url: String) {
        val key = normalizeSubscriptionUrl(url)
        if (key.isBlank()) return
        val profiles = loadProfiles()
        val doomed = profiles.filter {
            normalizeSubscriptionUrl(it.config.subscriptionUrl) == key
        }.map { it.id }.toSet()
        if (doomed.isEmpty()) return
        val activeId = prefs.getString("active_profile", null)
        val remaining = profiles.filterNot { it.id in doomed }
        if (activeId in doomed) {
            prefs.edit().putString("active_profile", remaining.firstOrNull()?.id ?: "").apply()
        }
        saveProfiles(remaining)
        getActiveProfile()?.let { writeEngineConfig(it) }
    }

    /** Убирает профили этой подписки, которых больше нет в свежем payload. */
    private fun pruneSubscription(url: String, keepIds: Set<String>) {
        val key = normalizeSubscriptionUrl(url)
        if (key.isBlank()) return
        val profiles = loadProfiles()
        val doomed = profiles.filter {
            normalizeSubscriptionUrl(it.config.subscriptionUrl) == key &&
                it.id !in keepIds
        }.map { it.id }.toSet()
        if (doomed.isEmpty()) return
        val activeId = prefs.getString("active_profile", null)
        val remaining = profiles.filterNot { it.id in doomed }
        if (activeId in doomed) {
            prefs.edit().putString("active_profile", remaining.firstOrNull()?.id ?: "").apply()
        }
        saveProfiles(remaining)
    }

    /**
     * Импорт подписки. Каждая подписка получает собственный набор профилей:
     * повторный импорт обновляет только её и не удаляет остальные подписки.
     *
     * @param select сделать первый профиль этой подписки активным
     *        (для фонового обновления из списка передавайте false).
     */
    fun importSubscription(sub: JSONObject, sourceUrl: String = "",
                           select: Boolean = true): VpnProfile {
        val user = sub.optJSONObject("user") ?: JSONObject()
        val uuid = user.optString("uuid", "")
        val secret = user.optString("secret", "")
        val userName = user.optString("name", "")
        val subBlock = sub.optJSONObject("subscription") ?: JSONObject()
        val url = sourceUrl.trim().ifBlank { subBlock.optString("url", "") }

        val nodes = sub.optJSONArray("nodes") ?: JSONArray()
        val nodeUrls = (0 until nodes.length()).mapNotNull { i ->
            nodes.optJSONObject(i)?.optString("url")?.trim()?.takeIf { it.isNotEmpty() }
        }
        val profilesArr = sub.optJSONArray("profiles") ?: JSONArray()
        val clientProfilesArr = sub.optJSONArray("client_profiles") ?: JSONArray()
        val routesArr = sub.optJSONArray("routes") ?: JSONArray()
        val canonicalRoutes = JSONArray()
        val seenRoutes = mutableSetOf<String>()
        fun addRoute(o: JSONObject?) {
            if (o == null) return
            val n = o.optString("name", "")
            if (n.isBlank() || !seenRoutes.add(n)) return
            canonicalRoutes.put(JSONObject().apply {
                put("name", n)
                put("hops", o.optJSONArray("hops") ?: JSONArray())
            })
        }
        // Новый формат: отдельный каталог маршрутов из конструктора админки.
        for (i in 0 until routesArr.length()) addRoute(routesArr.optJSONObject(i))
        // Старый формат: profiles[].routes.
        for (i in 0 until profilesArr.length()) {
            val routes = profilesArr.optJSONObject(i)?.optJSONArray("routes") ?: continue
            for (j in 0 until routes.length()) addRoute(routes.optJSONObject(j))
        }
        val routeNames = seenRoutes.toList()
        val split = sub.optJSONObject("split_routing") ?: JSONObject()
        val actions = split.optJSONObject("actions") ?: JSONObject()
        fun action(name: String): String {
            val a = actions.optJSONObject(name) ?: return ""
            if (a.optBoolean("direct", false)) return "direct"
            return a.optString("route", "")
        }

        val display = userName.ifBlank {
            url.removePrefix("https://").removePrefix("http://")
                .substringBefore("/").ifBlank { "Subscription" }
        }
        val normalizedUrl = normalizeSubscriptionUrl(url)
        val allProfiles = loadProfiles()
        // Одна и та же подписка узнаётся по URL. По user uuid — только
        // если URL вообще не пришёл (иначе разные подписки одного
        // пользователя схлопнулись бы в одну).
        val existing = allProfiles.firstOrNull {
            normalizedUrl.isNotBlank() &&
                normalizeSubscriptionUrl(it.config.subscriptionUrl) == normalizedUrl
        } ?: allProfiles.firstOrNull {
            normalizedUrl.isBlank() && uuid.isNotBlank() && it.config.userId == uuid
        }
        val base = existing?.config ?: getActiveProfile()?.config ?: ProxyConfig()
        // device_id уникален для подписки: иначе два разных пользователя
        // на одном сервере конфликтовали бы как "device owner mismatch".
        val deviceId = existing?.config?.deviceId?.takeIf { it.isNotBlank() }
            ?: UUID.randomUUID().toString()
        val slug = subscriptionSlug(url, uuid)

        // client_profiles: несколько профилей в одной подписке.
        val defs = if (clientProfilesArr.length() > 0) {
            (0 until clientProfilesArr.length()).mapNotNull { i ->
                clientProfilesArr.optJSONObject(i)?.let { ClientProfileDef.fromJson(it) }
            }.filter { it.enabled }
        } else emptyList()
        if (defs.isNotEmpty()) {
            // Определения именованных профилей — отдельно для каждой подписки,
            // чтобы импорт второй подписки не затирал первую.
            prefs.edit().putString(
                "client_profiles:$slug",
                JSONArray().apply { defs.forEach { put(it.toJson()) } }.toString()
            ).apply()
            val imported = mutableListOf<VpnProfile>()
            val keepIds = mutableSetOf<String>()
            for (cp in defs) {
                val cpId = cp.id.ifBlank { UUID.randomUUID().toString() }
                val localId = "sub:$slug:$cpId"
                // Старые версии использовали id "sub:<cpId>" без привязки
                // к подписке. Узнаём такой профиль по URL + имени и
                // переиспользуем его id (не плодим дубликаты).
                val existingProfile = allProfiles.firstOrNull { it.id == localId }
                    ?: allProfiles.firstOrNull {
                        normalizedUrl.isNotBlank() &&
                            normalizeSubscriptionUrl(it.config.subscriptionUrl) == normalizedUrl &&
                            it.name == cp.name
                    }
                val prev = existingProfile?.config
                val updated = base.copy(
                    subscriptionUrl = normalizedUrl,
                    subscriptionFile = "",
                    subscriptionName = display,
                    userId = uuid.ifBlank { base.userId },
                    userSecret = secret.ifBlank { base.userSecret },
                    deviceId = deviceId,
                    serverUrl = nodeUrls.firstOrNull() ?: base.serverUrl,
                    serverUrls = nodeUrls.ifEmpty { base.serverUrls },
                    nodesJson = nodes.toString(),
                    routesJson = canonicalRoutes.toString(),
                    routingEnabled = cp.splitEnabled,
                    routingOptions = if (routeNames.isNotEmpty())
                        routeNames.distinct().joinToString("|") else base.routingOptions,
                    routeRu = cp.routeRu.ifBlank { prev?.routeRu ?: "" },
                    routeNonRu = cp.routeNonRu.ifBlank { prev?.routeNonRu ?: "" },
                    routePrivate = cp.routePrivate.ifBlank { prev?.routePrivate ?: "direct" }
                )
                val profile = VpnProfile(
                    id = existingProfile?.id ?: localId,
                    name = cp.name,
                    mode = cp.mode,
                    config = updated,
                    routing = existingProfile?.routing ?: RoutingConfig()
                )
                if (existingProfile != null) updateProfile(profile) else addProfile(profile)
                imported.add(profile)
                keepIds.add(profile.id)
            }
            // Удаляем только профили этой подписки, исчезнувшие из payload.
            pruneSubscription(normalizedUrl, keepIds)
            if (select && imported.isNotEmpty()) selectProfile(imported.first().id)
            return imported.first()
        }

        val updated = base.copy(
            subscriptionUrl = normalizedUrl,
            subscriptionFile = "",
            subscriptionName = display,
            userId = uuid.ifBlank { base.userId },
            userSecret = secret.ifBlank { base.userSecret },
            deviceId = deviceId,
            serverUrl = nodeUrls.firstOrNull() ?: base.serverUrl,
            serverUrls = nodeUrls.ifEmpty { base.serverUrls },
            nodesJson = nodes.toString(),
            routesJson = canonicalRoutes.toString(),
            routingEnabled = if (existing != null)
                split.optBoolean("enabled", false) || base.routingEnabled
            else split.optBoolean("enabled", false),
            routingOptions = if (routeNames.isNotEmpty())
                routeNames.distinct().joinToString("|") else base.routingOptions,
            routeRu = if (existing != null) base.routeRu.ifBlank { action("ru") }
            else action("ru"),
            routeNonRu = if (existing != null) base.routeNonRu.ifBlank { action("non_ru") }
            else action("non_ru"),
            routePrivate = if (existing != null)
                base.routePrivate.ifBlank { "direct" }
            else action("private").ifBlank { "direct" }
        )
        val profile = if (existing != null) existing.copy(config = updated)
        else VpnProfile(id = "sub:$slug:default", name = display, config = updated)
        if (existing != null) updateProfile(profile) else addProfile(profile)
        pruneSubscription(normalizedUrl, setOf(profile.id))
        if (select) selectProfile(profile.id)
        return profile
    }

    // ── Legacy API (Simple tab + service) ─────────────────────────────

    fun load(): ProxyConfig {
        val active = getActiveProfile() ?: return ProxyConfig()
        val cfg = active.config
        if (cfg.deviceId.isBlank()) {
            val updated = active.copy(config = cfg.copy(deviceId = UUID.randomUUID().toString()))
            updateProfile(updated)
            return updated.config
        }
        return cfg
    }

    fun save(config: ProxyConfig) {
        val active = getActiveProfile()
        if (active != null) {
            updateProfile(active.copy(config = config))
        } else {
            // Профилей нет — создаём первый, чтобы настройки было куда сохранить.
            val profile = VpnProfile(name = "Default", config = config)
            addProfile(profile)
            selectProfile(profile.id)
        }
    }

    fun saveRaw(json: String) {
        configFile.writeText(json)
        parseRaw(json)?.let { parsed ->
            val active = getActiveProfile()
            if (active != null) {
                updateProfile(active.copy(config = parsed))
            } else {
                val profile = VpnProfile(name = "Default", config = parsed)
                addProfile(profile)
                selectProfile(profile.id)
            }
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
