package com.vpnproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.Configuration
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import android.net.VpnService
import android.net.Uri
import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject
import java.util.Locale
import java.util.UUID

data class LogEntry(val id: Long, val text: String)

private fun isNewerVersion(latest: String, current: String): Boolean {
    fun parts(v: String) = v.split('.').mapNotNull { it.filter { c -> c.isDigit() }.toIntOrNull() }
    val a = parts(latest)
    val b = parts(current)
    for (i in 0 until maxOf(a.size, b.size)) {
        val x = a.getOrElse(i) { 0 }
        val y = b.getOrElse(i) { 0 }
        if (x != y) return x > y
    }
    return false
}

/** Живое состояние URL из Python-движка: включён, карантин, счётчик ошибок. */
data class UrlRuntimeStatus(
    val url: String,
    val enabled: Boolean,
    val quarantined: Boolean,
    val cooldownRemaining: Int,
    val errors: Int,
)

/** Простая локализация без AppCompat: строки подставляются в Compose. */
object L {
    @Volatile
    var ru: Boolean = true

    fun t(en: String, ru: String): String = if (this.ru) ru else en
}

private fun tr(en: String, ru: String): String = L.t(en, ru)

class MainActivity : ComponentActivity() {
    private lateinit var configManager: ConfigManager
    private var logSeq = 0L
    private val logs = mutableStateListOf<LogEntry>()
    private val updateAvailable = mutableStateOf<String?>(null)
    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.getStringExtra("msg")?.let { msg ->
                logs.add(LogEntry(++logSeq, msg))
                if (logs.size > 3000) logs.removeAt(0)
            }
        }
    }

    // Единственный источник истины о состоянии прокси/VPN: сервисы широковещательно
    // сообщают running = true/false через STATE. Кнопка Start/Stop синхронизируется
    // с реальным состоянием (в т.ч. когда VPN отзывается системой из-за другого VPN).
    val isRunning = mutableStateOf(false)

    // Живой статус URL (карантин/ошибки), приходит из ProxyService раз в ~1.5с.
    val urlStatus = mutableStateOf<List<UrlRuntimeStatus>>(emptyList())

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.vpnproxy.STATE") {
                val running = intent.getBooleanExtra("running", false)
                isRunning.value = running
                if (!running) urlStatus.value = emptyList()
            }
        }
    }

    private val urlStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != ProxyService.ACTION_URL_STATUS) return
            val json = intent.getStringExtra("status") ?: return
            urlStatus.value = try {
                val arr = org.json.JSONArray(json)
                (0 until arr.length()).map { i ->
                    val o = arr.getJSONObject(i)
                    UrlRuntimeStatus(
                        url = o.optString("url"),
                        enabled = o.optBoolean("enabled", true),
                        quarantined = o.optBoolean("quarantined", false),
                        cooldownRemaining = o.optInt("cooldown_remaining", 0),
                        errors = o.optInt("errors", 0),
                    )
                }
            } catch (_: Exception) {
                emptyList()
            }
        }
    }

    private val vpnConsentReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.vpnproxy.REQUEST_VPN_CONSENT") {
                // Пришло из Quick Settings tile: нужен запрос согласия на VPN,
                // который может открыть только Activity.
                startProxyWithVpnCheck()
            }
        }
    }

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            logs.add(LogEntry(++logSeq, "VPN permission granted. Starting service..."))
            startProxy(this)
        } else {
            logs.add(LogEntry(++logSeq, "VPN permission denied"))
        }
    }

    fun startProxyWithVpnCheck() {
        val profile = configManager.getActiveProfile() ?: return
        if (profile.mode == "vpn") {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnConsent.launch(intent)
                return
            }
        }
        startProxy(this)
    }

    override fun attachBaseContext(newBase: Context) {
        val prefs = newBase.getSharedPreferences("vpnproxy", Context.MODE_PRIVATE)
        val language = prefs.getString("language", "ru") ?: "ru"
        val config = Configuration(newBase.resources.configuration)
        config.setLocale(Locale(language))
        super.attachBaseContext(newBase.createConfigurationContext(config))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        L.ru = resources.configuration.locales[0].language == "ru"
        configManager = ConfigManager(this)

        // Отражаем фактическое состояние сервиса (полезно после рестарта процесса,
        // когда сервис уже работает — START_STICKY).
        isRunning.value = ProxyService.isProxyRunning

        val filter = IntentFilter("com.vpnproxy.LOG")
        ContextCompat.registerReceiver(this, logReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        ContextCompat.registerReceiver(this, stateReceiver, IntentFilter("com.vpnproxy.STATE"),
            ContextCompat.RECEIVER_NOT_EXPORTED)
        ContextCompat.registerReceiver(this, urlStatusReceiver,
            IntentFilter(ProxyService.ACTION_URL_STATUS), ContextCompat.RECEIVER_NOT_EXPORTED)
        ContextCompat.registerReceiver(this, vpnConsentReceiver, IntentFilter("com.vpnproxy.REQUEST_VPN_CONSENT"),
            ContextCompat.RECEIVER_NOT_EXPORTED)

        val prefs = getSharedPreferences("vpnproxy", Context.MODE_PRIVATE)
        if (prefs.getBoolean("check_updates", true)) {
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val conn = URL("https://api.github.com/repos/victor-osipov-dev/short-polling-vpn/releases/latest")
                        .openConnection() as HttpURLConnection
                    conn.connectTimeout = 8000
                    conn.readTimeout = 8000
                    val body = conn.inputStream.bufferedReader().use { it.readText() }
                    val tag = JSONObject(body).optString("tag_name").removePrefix("v")
                    if (tag.isNotEmpty() && isNewerVersion(tag, BuildConfig.VERSION_NAME)) {
                        withContext(Dispatchers.Main) { updateAvailable.value = tag }
                    }
                } catch (_: Exception) {
                    // Network may be unavailable — never block the UI for this.
                }
            }
        }

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF4DA3FF),
                    onPrimary = Color.White,
                    secondary = Color(0xFF34D399),
                    onSecondary = Color(0xFF04120C),
                    background = Color(0xFF0B1020),
                    onBackground = Color.White,
                    surface = Color(0xFF141A2E),
                    onSurface = Color.White,
                    surfaceVariant = Color(0xFF1B2440),
                    onSurfaceVariant = Color(0xFFB8C2D9),
                    error = Color(0xFFF87171),
                )
            ) {
                MainScreen(configManager, logs, isRunning, urlStatus.value)
                UpdateDialog(updateAvailable.value) { updateAvailable.value = null }
            }
        }
    }

    override fun onDestroy() {
        unregisterReceiver(logReceiver)
        unregisterReceiver(stateReceiver)
        unregisterReceiver(urlStatusReceiver)
        unregisterReceiver(vpnConsentReceiver)
        super.onDestroy()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    configManager: ConfigManager,
    logs: SnapshotStateList<LogEntry>,
    isRunning: MutableState<Boolean>,
    urlStatus: List<UrlRuntimeStatus>,
) {
    var showSettings by remember { mutableStateOf(false) }
    var settingsTab by remember { mutableIntStateOf(0) }

    // Список приложений грузится один раз асинхронно на IO и кэшируется на уровне
    // MainScreen (он всегда в композиции), а не на вкладке Profiles — иначе он
    // пересчитывался бы (сотни синхронных binder-вызовов) при каждом переключении вкладки.
    val appContext = LocalContext.current
    var installedApps by remember { mutableStateOf<List<AppRule>>(emptyList()) }
    LaunchedEffect(Unit) {
        installedApps = withContext(Dispatchers.IO) { getInstalledApps(appContext) }
    }

    var profiles by remember { mutableStateOf(configManager.loadProfiles()) }
    var activeId by remember { mutableStateOf(configManager.getActiveProfile()?.id ?: "") }

    fun refreshProfiles() {
        profiles = configManager.loadProfiles()
        activeId = configManager.getActiveProfile()?.id ?: ""
    }

    // Возвращаясь с экрана настроек, подхватываем изменения профилей/конфига.
    LaunchedEffect(showSettings) {
        if (!showSettings) refreshProfiles()
    }

    if (showSettings) {
        SettingsScreen(
            configManager = configManager,
            logs = logs,
            installedApps = installedApps,
            selectedTab = settingsTab,
            urlStatus = urlStatus,
            isRunning = isRunning.value,
            onResetUrlErrors = { resetUrlErrors(appContext) },
            onRestartVpn = { restartProxy(appContext) },
            onTabChange = { settingsTab = it },
            onBack = { showSettings = false },
        )
    } else {
        HomeScreen(
            configManager = configManager,
            profiles = profiles,
            activeId = activeId,
            isRunning = isRunning,
            onRefreshProfiles = { refreshProfiles() },
            onSelectProfile = { id ->
                configManager.selectProfile(id)
                refreshProfiles()
            },
            onOpenSettings = { settingsTab = 0; showSettings = true },
            onManageProfiles = { settingsTab = 0; showSettings = true },
        )
    }
}

// ── Home screen: big connect button + profiles ────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    configManager: ConfigManager,
    profiles: List<VpnProfile>,
    activeId: String,
    isRunning: MutableState<Boolean>,
    onRefreshProfiles: () -> Unit,
    onSelectProfile: (String) -> Unit,
    onOpenSettings: () -> Unit,
    onManageProfiles: () -> Unit,
) {
    val context = LocalContext.current
    val active = profiles.firstOrNull { it.id == activeId } ?: profiles.firstOrNull()
    val scroll = rememberScrollState()
    val scope = rememberCoroutineScope()
    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    var showManual by remember { mutableStateOf(false) }
    var manualText by remember { mutableStateOf("") }
    var importStatus by remember { mutableStateOf("") }

    fun importSubscriptionText(raw: String, select: Boolean = true) {
        val text = raw.trim()
        if (text.isEmpty()) return
        importStatus = tr("Loading…", "Загрузка…")
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    val jsonText: String
                    var sourceUrl = ""
                    if (text.startsWith("{")) {
                        jsonText = text
                    } else {
                        sourceUrl = text
                        val conn = java.net.URL(text).openConnection() as java.net.HttpURLConnection
                        conn.connectTimeout = 10_000
                        conn.readTimeout = 20_000
                        conn.setRequestProperty("User-Agent", "vpn-client/1.0")
                        val code = conn.responseCode
                        if (code !in 200..299) {
                            return@withContext tr("Error: HTTP $code", "Ошибка: HTTP $code")
                        }
                        jsonText = conn.inputStream.bufferedReader().use { it.readText() }
                    }
                    val sub = org.json.JSONObject(jsonText)
                    val profile = configManager.importSubscription(sub, sourceUrl, select)
                    tr("OK: ${profile.name}", "OK: ${profile.name}")
                } catch (e: Exception) {
                    tr("Error: ${e.message ?: e.javaClass.simpleName}",
                       "Ошибка: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            importStatus = result
            if (result.startsWith("OK")) onRefreshProfiles()
        }
    }

    fun pasteFromClipboard() {
        val clip = clipboard.primaryClip
        if (clip != null && clip.itemCount > 0) {
            importSubscriptionText(clip.getItemAt(0).coerceToText(context).toString())
        } else {
            importStatus = tr("Clipboard is empty", "Буфер обмена пуст")
        }
    }

    val qrLauncher = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { importSubscriptionText(it) }
    }
    val qrOptions = remember {
        ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("VPN subscription QR")
            setBeepEnabled(false)
            setOrientationLocked(true)
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF0B1020), Color(0xFF111B33), Color(0xFF0B1020))
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scroll)
                .padding(horizontal = 20.dp, vertical = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            HomeHeader(onOpenSettings)
            Spacer(Modifier.height(18.dp))
            StatusPill(isRunning.value)
            Spacer(Modifier.height(8.dp))

            VpnPowerButton(isRunning.value) {
                if (isRunning.value) {
                    stopProxy(context)
                } else {
                    val activity = context as? MainActivity
                    if (activity != null) activity.startProxyWithVpnCheck() else startProxy(context)
                }
            }
            Text(
                text = if (isRunning.value) tr("Tap to disconnect", "Нажмите, чтобы отключиться")
                else tr("Tap to connect", "Нажмите, чтобы подключиться"),
                color = Color.White.copy(alpha = 0.55f),
                fontSize = 13.sp
            )

            Spacer(Modifier.height(18.dp))
            Text(
                text = active?.name ?: tr("No profile", "Нет профиля"),
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold
            )

            Spacer(Modifier.height(30.dp))
            SubscriptionCard(
                active = active,
                status = importStatus,
                onPaste = { pasteFromClipboard() },
                onQr = { qrLauncher.launch(qrOptions) },
                onManual = { showManual = true },
                onRefresh = {
                    val url = active?.config?.subscriptionUrl.orEmpty()
                    if (url.isNotBlank()) importSubscriptionText(url)
                    else importStatus = tr("No subscription on this profile",
                                           "У этого профиля нет подписки")
                },
            )
            Spacer(Modifier.height(18.dp))
            ProfilesSection(
                profiles = profiles,
                activeId = activeId,
                running = isRunning.value,
                onSelectProfile = onSelectProfile,
                onManageProfiles = onManageProfiles,
                onRefreshSubscription = { p ->
                    val url = p.config.subscriptionUrl
                    if (url.isNotBlank()) {
                        importSubscriptionText(url, select = false)
                    } else {
                        importStatus = tr("No subscription on this profile",
                                           "У этого профиля нет подписки")
                    }
                },
                onDeleteSubscription = { url ->
                    configManager.deleteSubscription(url)
                    onRefreshProfiles()
                },
            )
            Spacer(Modifier.height(24.dp))
        }
    }

    if (showManual) {
        AlertDialog(
            onDismissRequest = { showManual = false },
            title = { Text(tr("Add subscription", "Добавить подписку")) },
            text = {
                OutlinedTextField(
                    value = manualText,
                    onValueChange = { manualText = it },
                    minLines = 4,
                    maxLines = 8,
                    label = { Text(tr("Subscription URL or JSON", "URL подписки или JSON")) },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = Color(0xFF4DA3FF),
                        cursorColor = Color(0xFF4DA3FF),
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showManual = false
                    importSubscriptionText(manualText)
                    manualText = ""
                }) { Text(tr("Add", "Добавить")) }
            },
            dismissButton = {
                TextButton(onClick = { showManual = false }) {
                    Text(tr("Cancel", "Отмена"))
                }
            }
        )
    }
}

@Composable
private fun SubscriptionCard(
    active: VpnProfile?,
    status: String,
    onPaste: () -> Unit,
    onQr: () -> Unit,
    onManual: () -> Unit,
    onRefresh: () -> Unit,
) {
    val cfg = active?.config
    val name = cfg?.subscriptionName.orEmpty()
        .ifBlank { cfg?.userId?.take(8)?.let { "ID $it" } ?: tr("No subscription", "Нет подписки") }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF141A2E)),
        border = BorderStroke(1.dp, Color(0xFF4DA3FF).copy(alpha = 0.25f))
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(tr("Subscription", "Подписка"), color = Color.White,
                 fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Text(name, color = Color(0xFF9CC9FF), fontSize = 13.sp)
            val subUrlText = cfg?.subscriptionUrl
            if (!subUrlText.isNullOrBlank()) {
                Text(subUrlText, color = Color.White.copy(alpha = 0.45f),
                     fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Button(
                onClick = onPaste,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(52.dp),
                shape = RoundedCornerShape(14.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2563EB))
            ) {
                Text(
                    tr("Add subscription", "Добавить подписку"),
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onQr, modifier = Modifier.weight(1f)) {
                    Text("QR")
                }
                OutlinedButton(onClick = onManual, modifier = Modifier.weight(1f)) {
                    Text(tr("Manual", "Вручную"))
                }
            }
            if (!cfg?.subscriptionUrl.isNullOrBlank()) {
                TextButton(onClick = onRefresh, contentPadding = PaddingValues(0.dp)) {
                    Text(tr("Refresh subscription", "Обновить подписку"), fontSize = 12.sp)
                }
            }
            if (status.isNotEmpty()) {
                Text(
                    status, fontSize = 12.sp,
                    color = if (status.startsWith("OK")) Color(0xFF34D399) else Color(0xFFFFB74D)
                )
            }
        }
    }
}

@Composable
private fun HomeHeader(onOpenSettings: () -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(tr("Internet", "Интернет"), color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
            Text(tr("Secure tunnel", "Защищённый туннель"),
                 color = Color.White.copy(alpha = 0.5f), fontSize = 12.sp)
        }
        IconButton(onClick = onOpenSettings) {
            Icon(
                Icons.Default.Settings,
                contentDescription = "Settings",
                tint = Color.White.copy(alpha = 0.8f)
            )
        }
    }
}

@Composable
private fun StatusPill(running: Boolean) {
    val color = if (running) Color(0xFF34D399) else Color(0xFF8A93A6)
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.12f))
            .padding(horizontal = 14.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        Text(
            text = if (running) tr("Connected", "Подключено") else tr("Disconnected", "Отключено"),
            color = color,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium
        )
    }
}

@Composable
private fun VpnPowerButton(running: Boolean, onClick: () -> Unit) {
    val transition = rememberInfiniteTransition(label = "pulse")
    val pulse by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulse"
    )
    val accent by animateColorAsState(
        targetValue = if (running) Color(0xFF34D399) else Color(0xFF4DA3FF),
        label = "accent"
    )
    val accentDark by animateColorAsState(
        targetValue = if (running) Color(0xFF059669) else Color(0xFF2563EB),
        label = "accentDark"
    )

    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(240.dp)) {
        Canvas(Modifier.fillMaxSize()) {
            val maxR = size.minDimension / 2f
            if (running) {
                drawCircle(
                    color = accent.copy(alpha = 0.10f * (1f - pulse)),
                    radius = maxR * (0.62f + 0.38f * pulse)
                )
                drawCircle(
                    color = accent.copy(alpha = 0.16f * (1f - pulse)),
                    radius = maxR * (0.55f + 0.25f * pulse)
                )
            } else {
                drawCircle(color = Color.White.copy(alpha = 0.04f), radius = maxR)
            }
            drawCircle(
                color = accent.copy(alpha = 0.18f),
                radius = maxR * 0.82f,
                style = Stroke(width = 1.dp.toPx())
            )
        }
        Box(
            modifier = Modifier
                .size(184.dp)
                .clip(CircleShape)
                .background(Brush.verticalGradient(listOf(accent, accentDark)))
                .clickable(onClick = onClick),
            contentAlignment = Alignment.Center
        ) {
            PowerGlyph(Color.White)
        }
    }
}

@Composable
private fun PowerGlyph(color: Color) {
    Canvas(Modifier.size(64.dp)) {
        val stroke = 6.dp.toPx()
        val r = size.minDimension / 2f - stroke / 2f
        drawArc(
            color = color,
            startAngle = -50f,
            sweepAngle = 280f,
            useCenter = false,
            topLeft = Offset(center.x - r, center.y - r),
            size = Size(r * 2f, r * 2f),
            style = Stroke(width = stroke, cap = StrokeCap.Round)
        )
        drawLine(
            color = color,
            start = Offset(center.x, 4.dp.toPx()),
            end = Offset(center.x, size.height * 0.46f),
            strokeWidth = stroke,
            cap = StrokeCap.Round
        )
    }
}

@Composable
private fun ProfilesSection(
    profiles: List<VpnProfile>,
    activeId: String,
    running: Boolean,
    onSelectProfile: (String) -> Unit,
    onManageProfiles: () -> Unit,
    onRefreshSubscription: (VpnProfile) -> Unit,
    onDeleteSubscription: (String) -> Unit,
) {
    val context = LocalContext.current
    var pendingDelete by remember { mutableStateOf<Pair<String, String>?>(null) }
    val groups = profiles.groupBy { it.config.subscriptionUrl.trim() }

    Column(Modifier.fillMaxWidth()) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                tr("Profiles", "Профили"),
                color = Color.White,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.weight(1f)
            )
            TextButton(onClick = onManageProfiles) { Text(tr("Manage", "Управление")) }
        }
        if (running) {
            Text(
                tr("Reconnect to apply profile changes", "Переподключитесь, чтобы применить изменения"),
                color = Color.White.copy(alpha = 0.45f),
                fontSize = 11.sp
            )
            Spacer(Modifier.height(6.dp))
        }

        groups.forEach { (subUrl, groupProfiles) ->
            val first = groupProfiles.firstOrNull() ?: return@forEach
            val title = first.config.subscriptionName.takeIf { it.isNotBlank() }
                ?: tr("Local profiles", "Локальные профили")
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        title,
                        color = Color.White,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        if (subUrl.isNotBlank())
                            tr("${groupProfiles.size} profile(s) in subscription",
                               "Профилей в подписке: ${groupProfiles.size}")
                        else tr("${groupProfiles.size} local profile(s)",
                                "Локальных профилей: ${groupProfiles.size}"),
                        color = Color.White.copy(alpha = 0.4f),
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                TextButton(
                    onClick = { ProfileTester.test(context, groupProfiles) },
                    contentPadding = PaddingValues(horizontal = 8.dp)
                ) {
                    Text(tr("Test all", "Тест всех"), fontSize = 12.sp)
                }
                if (subUrl.isNotBlank()) {
                    SubscriptionMenu(
                        onRefresh = { onRefreshSubscription(first) },
                        onDelete = { pendingDelete = subUrl to title },
                    )
                }
            }
            Spacer(Modifier.height(6.dp))
            groupProfiles.forEach { p ->
                ProfileCard(
                    profile = p,
                    active = p.id == activeId,
                    test = ProfileTester.results[p.id],
                    onClick = { onSelectProfile(p.id) },
                    onTest = { ProfileTester.test(context, listOf(p)) },
                )
                Spacer(Modifier.height(10.dp))
            }
            Spacer(Modifier.height(4.dp))
        }
    }

    pendingDelete?.let { (url, name) ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(tr("Delete subscription", "Удалить подписку")) },
            text = {
                Text(tr("Delete \"$name\" and all its profiles? Other subscriptions stay.",
                        "Удалить \"$name\" и все её профили? Другие подписки останутся."))
            },
            confirmButton = {
                TextButton(onClick = {
                    onDeleteSubscription(url)
                    pendingDelete = null
                }) { Text(tr("Delete", "Удалить")) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(tr("Cancel", "Отмена"))
                }
            }
        )
    }
}

@Composable
private fun SubscriptionMenu(onRefresh: () -> Unit, onDelete: () -> Unit) {
    var open by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { open = true }, contentPadding = PaddingValues(horizontal = 4.dp)) {
            Text("⋮", color = Color.White.copy(alpha = 0.7f), fontSize = 18.sp)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(
                text = { Text(tr("Refresh subscription", "Обновить подписку")) },
                onClick = {
                    open = false
                    onRefresh()
                }
            )
            DropdownMenuItem(
                text = { Text(tr("Delete subscription", "Удалить подписку")) },
                onClick = {
                    open = false
                    onDelete()
                }
            )
        }
    }
}

private fun testResultLine(r: ProfileTestResult): String = when {
    r.running -> tr("Checking connection…", "Проверка подключения…")
    r.ok == true -> buildString {
        append(if (r.latencyMs > 0) "${r.latencyMs} ms" else "OK")
        if (r.exitIp.isNotBlank()) append(" · exit ").append(r.exitIp)
        if (r.route.isNotBlank()) append(" · ").append(r.route)
    }
    else -> tr("Failed: ", "Ошибка: ") + r.error.ifBlank { "no response" }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProfileCard(
    profile: VpnProfile,
    active: Boolean,
    test: ProfileTestResult?,
    onClick: () -> Unit,
    onTest: () -> Unit,
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (active) Color(0xFF1B2A4A) else Color(0xFF141A2E)
        ),
        border = BorderStroke(
            1.dp,
            if (active) Color(0xFF4DA3FF).copy(alpha = 0.6f) else Color.White.copy(alpha = 0.08f)
        )
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(Color(0xFF4DA3FF).copy(alpha = if (active) 0.25f else 0.12f)),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    profile.name.take(1).uppercase(),
                    color = Color(0xFF9CC9FF),
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    profile.name,
                    color = Color.White,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = (if (profile.mode == "vpn") "VPN" else "Proxy"),
                    color = Color.White.copy(alpha = 0.5f),
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                test?.let { r ->
                    val color = when {
                        r.running -> Color(0xFF9CC9FF)
                        r.ok == true -> Color(0xFF7BE495)
                        else -> Color(0xFFFF8A80)
                    }
                    Text(
                        text = testResultLine(r),
                        color = color,
                        fontSize = 11.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            TextButton(
                onClick = onTest,
                contentPadding = PaddingValues(horizontal = 6.dp)
            ) {
                Text(tr("Test", "Тест"), fontSize = 12.sp)
            }
            RadioButton(
                selected = active,
                onClick = onClick,
                colors = RadioButtonDefaults.colors(
                    selectedColor = Color(0xFF4DA3FF),
                    unselectedColor = Color.White.copy(alpha = 0.35f)
                )
            )
        }
    }
}

private fun serverHost(url: String): String = try {
    java.net.URI(url).host ?: url
} catch (_: Exception) {
    url
}

// ── Settings screen (everything complex lives here) ───────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UpdateDialog(version: String?, onDismiss: () -> Unit) {
    if (version == null) return
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("vpnproxy", Context.MODE_PRIVATE)
    var checkUpdates by remember {
        mutableStateOf(prefs.getBoolean("check_updates", true))
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(tr("Update available", "Доступно обновление")) },
        text = {
            Column {
                Text("v${BuildConfig.VERSION_NAME} → v$version")
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = checkUpdates,
                        onCheckedChange = {
                            checkUpdates = it
                            prefs.edit().putBoolean("check_updates", it).apply()
                        }
                    )
                    Text(tr("Check for updates", "Проверять обновления"))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val intent = Intent(
                    Intent.ACTION_VIEW,
                    Uri.parse("https://github.com/victor-osipov-dev/short-polling-vpn/releases/latest")
                )
                context.startActivity(intent)
                onDismiss()
            }) { Text(tr("Download", "Скачать")) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("OK") }
        }
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    configManager: ConfigManager,
    logs: SnapshotStateList<LogEntry>,
    installedApps: List<AppRule>,
    selectedTab: Int,
    urlStatus: List<UrlRuntimeStatus>,
    isRunning: Boolean,
    onResetUrlErrors: () -> Unit,
    onRestartVpn: () -> Unit,
    onTabChange: (Int) -> Unit,
    onBack: () -> Unit,
) {
    var autoScroll by remember { mutableStateOf(true) }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(tr("Settings", "Настройки")) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = tr("Back", "Назад"))
                    }
                },
                actions = {
                    IconButton(onClick = onRestartVpn) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = tr("Restart VPN", "Перезапустить VPN")
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                    navigationIconContentColor = MaterialTheme.colorScheme.onSurface,
                    actionIconContentColor = MaterialTheme.colorScheme.onSurface,
                )
            )
        },
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            TabRow(
                selectedTabIndex = selectedTab,
                containerColor = MaterialTheme.colorScheme.surface
            ) {
                Tab(selected = selectedTab == 0, onClick = { onTabChange(0) },
                    text = { Text(tr("General", "Общее"), fontSize = 12.sp, maxLines = 1) })
                Tab(selected = selectedTab == 1, onClick = { onTabChange(1) },
                    text = { Text(tr("Connection", "Подключение"), fontSize = 12.sp, maxLines = 1) })
                Tab(selected = selectedTab == 2, onClick = { onTabChange(2) },
                    text = { Text(tr("Logs", "Логи"), fontSize = 12.sp, maxLines = 1) })
            }
            when (selectedTab) {
                0 -> ProfilesTab(configManager, installedApps)
                1 -> SimpleConfigTab(configManager, urlStatus, isRunning, onResetUrlErrors)
                2 -> LogTab(logs, autoScroll, { autoScroll = it })
            }
            Text(
                "Internet v${BuildConfig.VERSION_NAME}",
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
            )
        }
    }
}

// ── Simple config tab ─────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LanguageRow() {
    val context = LocalContext.current
    val prefs = context.getSharedPreferences("vpnproxy", Context.MODE_PRIVATE)
    var current by remember { mutableStateOf(prefs.getString("language", "ru") ?: "ru") }

    fun apply(lang: String) {
        current = lang
        prefs.edit().putString("language", lang).apply()
        val activity = context as? MainActivity ?: return
        activity.recreate()
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            tr("Language:", "Язык:"),
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        FilterChip(
            selected = current == "en",
            onClick = { apply("en") },
            label = { Text("English") }
        )
        FilterChip(
            selected = current == "ru",
            onClick = { apply("ru") },
            label = { Text("Русский") }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SimpleConfigTab(
    configManager: ConfigManager,
    runtimeStatus: List<UrlRuntimeStatus>,
    isRunning: Boolean,
    onResetUrlErrors: () -> Unit,
) {
    var cfg by remember { mutableStateOf(configManager.load()) }
    val scroll = rememberScrollState()
    var subUrl by remember { mutableStateOf(cfg.subscriptionUrl) }
    var subStatus by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    fun save(c: ProxyConfig) {
        cfg = c
        configManager.save(c)
    }

    fun applySubscription() {
        val url = subUrl.trim()
        if (url.isEmpty()) return
        subStatus = tr("Loading…", "Загрузка…")
        val baseCfg = cfg
        save(baseCfg.copy(subscriptionUrl = url, subscriptionFile = ""))
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 15_000
                    conn.setRequestProperty("User-Agent", "vpn-client/1.0")
                    val code = conn.responseCode
                    if (code !in 200..299) {
                        Pair(tr("Error: HTTP $code", "Ошибка: HTTP $code"), null)
                    } else {
                        val text = conn.inputStream.bufferedReader().use { it.readText() }
                        val sub = org.json.JSONObject(text)
                        val profile = configManager.importSubscription(sub, url)
                        val urls = profile.config.serverUrls
                        Pair(tr("OK: ${profile.name} (${urls.size} nodes)",
                                "OK: ${profile.name} (узлов ${urls.size})"), profile.config)
                    }
                } catch (e: Exception) {
                    Pair(tr("Error: ${e.message ?: e.javaClass.simpleName}",
                            "Ошибка: ${e.message ?: e.javaClass.simpleName}"), null)
                }
            }
            val updated = result.second
            if (updated != null) cfg = updated
            subStatus = result.first
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(tr("Subscription", "Подписка"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            OutlinedTextField(
                value = subUrl,
                onValueChange = {
                    subUrl = it
                    save(cfg.copy(subscriptionUrl = it.trim(), subscriptionFile = ""))
                },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text(tr("Subscription URL", "URL подписки")) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = MaterialTheme.colorScheme.primary,
                    unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
                    cursorColor = MaterialTheme.colorScheme.primary,
                )
            )
            Button(onClick = { applySubscription() }, enabled = subUrl.isNotBlank()) {
                Text(tr("Load", "Загрузить"))
            }
        }
        if (cfg.userId.isNotBlank()) {
            Text("Пользователь: ${cfg.userId}", fontSize = 11.sp,
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.55f))
        }
        if (subStatus.isNotEmpty()) {
            Text(
                subStatus,
                fontSize = 12.sp,
                color = if (subStatus.startsWith("OK")) Color(0xFF34D399) else Color(0xFFF87171)
            )
        }
        Text("Подписка обновляется при каждом подключении; узлы и маршруты приходят с сервера.",
             fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f))

        Text(tr("Routing", "Маршрутизация"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(tr("Split routing", "Раздельная маршрутизация"), color = MaterialTheme.colorScheme.onSurface,
                 modifier = Modifier.weight(1f))
            Switch(
                checked = cfg.routingEnabled,
                onCheckedChange = { save(cfg.copy(routingEnabled = it)) }
            )
        }
        if (cfg.routingEnabled) {
            val routeNames = cfg.routingOptions
                .split("|")
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .distinct()
            val options = (routeNames + "direct").distinct()
            if (routeNames.isEmpty()) {
                Text(tr("Load a subscription to get route names.",
                       "Загрузите подписку, чтобы получить названия маршрутов."),
                     fontSize = 11.sp,
                     color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f))
            } else {
                RouteSelector("RU", cfg.routeRu, options) {
                    save(cfg.copy(routeRu = it))
                }
                RouteSelector(tr("non-RU", "не-RU"), cfg.routeNonRu, options) {
                    save(cfg.copy(routeNonRu = it))
                }
                RouteSelector(tr("Private / LAN", "Локальная сеть"), cfg.routePrivate, options) {
                    save(cfg.copy(routePrivate = it))
                }
            }
        }

        Text(tr("Server URLs:", "Серверные URL:"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        cfg.effectiveServerUrls().forEachIndexed { i, url ->
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                val urlEnabled = url !in cfg.disabledUrls
                Checkbox(
                    checked = urlEnabled,
                    onCheckedChange = { checked ->
                        val normalized = url.trim()
                        val disabled = cfg.disabledUrls.toMutableList()
                        if (checked) {
                            disabled.removeAll { it == normalized }
                        } else if (normalized.isNotEmpty() && normalized !in disabled) {
                            disabled.add(normalized)
                        }
                        save(cfg.copy(disabledUrls = disabled))
                    },
                    modifier = Modifier.size(32.dp)
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { new ->
                        val list = cfg.effectiveServerUrls().toMutableList()
                        list[i] = new
                        val clean = list.map { it.trim() }.filter { it.isNotEmpty() }
                        save(cfg.copy(
                            serverUrl = clean.firstOrNull() ?: cfg.serverUrl,
                            serverUrls = clean
                        ))
                    },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                    label = { Text("URL ${i + 1}") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
                        cursorColor = MaterialTheme.colorScheme.primary,
                    )
                )
                TextButton(
                    onClick = {
                        val list = cfg.effectiveServerUrls().toMutableList()
                        if (list.size > 1) {
                            val removed = list.removeAt(i)
                            save(cfg.copy(
                                serverUrl = list.first(),
                                serverUrls = list,
                                disabledUrls = cfg.disabledUrls.filterNot { it == removed.trim() }
                            ))
                        }
                    },
                    enabled = cfg.effectiveServerUrls().size > 1,
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(32.dp)
                ) { Text("✕", fontSize = 15.sp) }
            }
        }
        Button(onClick = {
            val list = cfg.effectiveServerUrls() + ""
            save(cfg.copy(serverUrl = list.first(), serverUrls = list))
        }) { Text(tr("+ Add URL", "+ Добавить URL")) }

        UrlStatusSection(cfg, runtimeStatus, isRunning, onResetUrlErrors)

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("URL select:", "Выбор URL:"), color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = cfg.serverSelector == "round",
                onClick = { save(cfg.copy(serverSelector = "round")) },
                label = { Text(tr("Round", "По кругу")) }
            )
            FilterChip(
                selected = cfg.serverSelector == "random",
                onClick = { save(cfg.copy(serverSelector = "random")) },
                label = { Text(tr("Random", "Случайно")) }
            )
        }
        Text(
            when {
                cfg.routingEnabled && cfg.routingOptions.isNotBlank() ->
                    tr("URL select is only a fallback. For split traffic the entry server is chosen by the route from the subscription.",
                       "Выбор URL — только fallback. Для split-трафика entry выбирается маршрутом из подписки.")
                cfg.routingEnabled ->
                    tr("Split routing is on, but the route list is empty. URL select may still be used as a fallback.",
                       "Split routing включён, но список маршрутов пуст. Выбор URL может использоваться как fallback.")
                else ->
                    tr("Split routing is off: all connections use URL select.",
                       "Split routing выключен: все соединения используют выбор URL.")
            },
            fontSize = 11.sp,
            color = if (cfg.routingEnabled) Color(0xFFFFB74D)
                    else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
        )

        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                tr("Pad poll sizes", "Маскировать размеры poll"),
                color = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.weight(1f)
            )
            Switch(
                checked = cfg.padPolls,
                onCheckedChange = { save(cfg.copy(padPolls = it)) }
            )
        }
        Text(
            tr("Empty poll requests are padded to random sizes so the active entry is harder to spot by request size.",
               "Пустые poll-запросы дополняются случайным padding, чтобы активный entry было сложнее определить по размеру запроса."),
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
        )

        ConfigTextField("Poll Path", cfg.pollPath) { save(cfg.copy(pollPath = it)) }
        ConfigTextField("Host header (optional)", cfg.hostHeader) { save(cfg.copy(hostHeader = it)) }
        ConfigTextField("PSK", cfg.psk, singleLine = false) { save(cfg.copy(psk = it)) }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ConfigTextField("Poll interval (ms)", cfg.pollIntervalMs.toString(),
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(pollIntervalMs = v)) } }

            ConfigTextField("Max chunk", cfg.maxChunkBytes.toString(),
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(maxChunkBytes = v)) } }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ConfigTextField("SOCKS port", cfg.socksBindPort.toString(),
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(socksBindPort = v)) } }

            ConfigTextField("HMAC window (s)", cfg.hmacWindowSeconds.toString(),
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(hmacWindowSeconds = v)) } }
        }

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("Method:", "Метод:"), color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = cfg.pollMethod == "GET",
                onClick = { save(cfg.copy(pollMethod = "GET")) },
                label = { Text("GET") }
            )
            FilterChip(
                selected = cfg.pollMethod == "POST",
                onClick = { save(cfg.copy(pollMethod = "POST")) },
                label = { Text("POST") }
            )
        }

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("Data in:", "Данные в:"), color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = cfg.pollDataIn == "body",
                onClick = { save(cfg.copy(pollDataIn = "body")) },
                label = { Text("body") }
            )
            FilterChip(
                selected = cfg.pollDataIn == "header",
                onClick = { save(cfg.copy(pollDataIn = "header")) },
                label = { Text("header") }
            )
        }

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("Verify TLS:", "Проверять TLS:"), color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.verifyTls,
                onCheckedChange = { save(cfg.copy(verifyTls = it)) })
        }

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("Log level:", "Уровень логов:"), color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = cfg.loggingLevel == "DEBUG",
                onClick = { save(cfg.copy(loggingLevel = "DEBUG")) },
                label = { Text("DEBUG") }
            )
            FilterChip(
                selected = cfg.loggingLevel == "INFO",
                onClick = { save(cfg.copy(loggingLevel = "INFO")) },
                label = { Text("INFO") }
            )
        }

        Text(tr("Idle timeout:", "Idle-таймаут:"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(tr("Enabled:", "Включено:"), color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.idleTimeoutEnabled,
                onCheckedChange = { save(cfg.copy(idleTimeoutEnabled = it)) })
            Spacer(Modifier.weight(1f))
            ConfigTextField("Timeout (s)", cfg.idleTimeoutSeconds.toString(),
                modifier = Modifier.width(120.dp).weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(idleTimeoutSeconds = v)) } }
        }

        Text(tr("DNS relay:", "DNS-релей:"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(tr("Enabled:", "Включено:"), color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.dnsRelayEnabled,
                onCheckedChange = { save(cfg.copy(dnsRelayEnabled = it)) })
            Spacer(Modifier.weight(1f))
            ConfigTextField("Port", cfg.dnsBindPort.toString(),
                modifier = Modifier.width(120.dp).weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(dnsBindPort = v)) } }
        }

        Divider()
        Text(tr("Advanced config", "Продвинутый конфиг"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        RawConfigEditor(configManager)
    }
}

@Composable
fun RawConfigEditor(configManager: ConfigManager) {
    RawConfigTab(configManager, embedded = true)
}

@Composable
fun ConfigTextField(
    label: String, value: String,
    modifier: Modifier = Modifier,
    singleLine: Boolean = true,
    keyboardType: KeyboardType = KeyboardType.Text,
    onValueChange: (String) -> Unit
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier.fillMaxWidth(),
        singleLine = singleLine,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = MaterialTheme.colorScheme.primary,
            unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
            focusedLabelColor = MaterialTheme.colorScheme.primary,
            unfocusedLabelColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
            cursorColor = MaterialTheme.colorScheme.primary,
        )
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RouteSelector(
    label: String,
    value: String,
    options: List<String>,
    onSelect: (String) -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Text(
            label,
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            options.forEach { option ->
                FilterChip(
                    selected = value == option,
                    onClick = { onSelect(option) },
                    label = { Text(if (option == "direct") "Direct" else option) }
                )
            }
        }
    }
}

// ── URL status (quarantine / errors) ─────────────────────────────────

@Composable
fun UrlStatusSection(
    cfg: ProxyConfig,
    runtimeStatus: List<UrlRuntimeStatus>,
    isRunning: Boolean,
    onResetErrors: () -> Unit,
) {
    val urls = cfg.effectiveServerUrls().filter { it.isNotBlank() }
    val runtime = runtimeStatus.associateBy { it.url.trimEnd('/') }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0F1526)),
        border = BorderStroke(1.dp, Color.White.copy(alpha = 0.06f)),
        shape = RoundedCornerShape(14.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    tr("URL status", "Статус URL"),
                    color = MaterialTheme.colorScheme.onSurface,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = onResetErrors, enabled = isRunning) {
                    Text(tr("Reset errors", "Сбросить ошибки"), fontSize = 12.sp)
                }
            }

            if (urls.isEmpty()) {
                Text(
                    tr("No server URLs configured", "URL серверов не настроены"),
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    fontSize = 12.sp
                )
            }

            urls.forEach { url ->
                val r = runtime[url.trimEnd('/')]
                // Пока сервис запущен, доверяем фактическому состоянию движка,
                // иначе — сохранённой настройке (что включено/выключено).
                val disabled = if (isRunning && r != null) !r.enabled else url in cfg.disabledUrls
                val label: String
                val color: Color
                when {
                    disabled -> {
                        label = tr("Disabled", "Отключён")
                        color = Color(0xFF8A93A6)
                    }
                    r?.quarantined == true -> {
                        label = tr("Quarantine", "Карантин") + " · ${r.cooldownRemaining}s"
                        color = Color(0xFFFFB74D)
                    }
                    r != null && r.errors > 0 -> {
                        label = tr("Active", "Активен") + " · ${r.errors} " + tr("error(s)", "ошиб.")
                        color = Color(0xFFF87171)
                    }
                    else -> {
                        label = tr("Active", "Активен")
                        color = Color(0xFF34D399)
                    }
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        Modifier
                            .size(8.dp)
                            .clip(CircleShape)
                            .background(color)
                    )
                    Column(Modifier.weight(1f)) {
                        Text(
                            url,
                            color = MaterialTheme.colorScheme.onSurface,
                            fontSize = 12.sp,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Text(label, color = color, fontSize = 11.sp)
                    }
                }
            }

            Text(
                text = if (isRunning) "URL changes and quarantine time apply after reconnect."
                else "Connect to see live quarantine state.",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f),
                fontSize = 11.sp
            )
        }
    }
}

// ── Profiles tab ──────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesTab(configManager: ConfigManager, installedApps: List<AppRule>) {
    var profiles by remember { mutableStateOf(configManager.loadProfiles()) }
    var activeId by remember { mutableStateOf(configManager.getActiveProfile()?.id ?: "") }
    var editing by remember { mutableStateOf(configManager.getActiveProfile() ?: VpnProfile()) }
    var showNameDialog by remember { mutableStateOf(false) }
    var dialogKind by remember { mutableStateOf("new") } // new | rename | duplicate
    var showAppPicker by remember { mutableStateOf(false) }
    var pickerList by remember { mutableStateOf("allow") } // allow | block
    var pendingDelete by remember { mutableStateOf<VpnProfile?>(null) }

    fun refresh() {
        profiles = configManager.loadProfiles()
        activeId = configManager.getActiveProfile()?.id ?: ""
        editing = configManager.getActiveProfile() ?: VpnProfile()
    }

    fun persist(p: VpnProfile) {
        configManager.updateProfile(p)
        editing = p
        profiles = configManager.loadProfiles()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        LanguageRow()
        Divider()
        Text(tr("Profiles", "Профили"), style = MaterialTheme.typography.titleMedium,
             color = MaterialTheme.colorScheme.onSurface)
        Text(tr("Each profile stores mode, connection settings and routing. Switch, then Stop/Start to apply.", "Каждый профиль хранит режим, настройки подключения и маршрутизацию. Переключите и перезапустите VPN."),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)

        // Profile selector cards: tap makes active + editable
        profiles.forEach { p ->
            val isActive = p.id == activeId
            Card(
                onClick = {
                    configManager.selectProfile(p.id)
                    activeId = p.id
                    editing = p
                },
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (isActive) MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
                    else MaterialTheme.colorScheme.surface
                )
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth().padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(p.name, color = MaterialTheme.colorScheme.onSurface,
                             fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                        Text(if (p.mode == "vpn") "VPN mode" else "Proxy (SOCKS5) mode",
                             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
                    }
                    if (isActive) {
                        Text(tr("ACTIVE", "АКТИВЕН"), color = MaterialTheme.colorScheme.primary, fontSize = 11.sp)
                    }
                    TextButton(onClick = {
                        pendingDelete = p
                    }) {
                        Text("✕", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 14.sp)
                    }
                }
            }
        }

        pendingDelete?.let { doomed ->
            AlertDialog(
                onDismissRequest = { pendingDelete = null },
                title = { Text(tr("Delete profile", "Удалить профиль")) },
                text = { Text(tr("Delete \"${doomed.name}\"? This cannot be undone.",
                                 "Удалить \"${doomed.name}\"? Это нельзя отменить.")) },
                confirmButton = {
                    TextButton(onClick = {
                        configManager.deleteProfile(doomed.id)
                        pendingDelete = null
                        refresh()
                    }) { Text(tr("Delete", "Удалить")) }
                },
                dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text(tr("Cancel", "Отмена")) } }
            )
        }

        Divider()

        // Editing section
        Text("Edit: \"${editing.name}\"", style = MaterialTheme.typography.titleSmall,
             color = MaterialTheme.colorScheme.onSurface)

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { dialogKind = "new"; showNameDialog = true },
                modifier = Modifier.weight(1f)
            ) { Text(tr("New", "Новый"), maxLines = 1, fontSize = 13.sp) }
            Button(
                onClick = { dialogKind = "rename"; showNameDialog = true },
                modifier = Modifier.weight(1f)
            ) { Text(tr("Rename", "Переименовать"), maxLines = 1, fontSize = 13.sp) }
            Button(
                onClick = { dialogKind = "duplicate"; showNameDialog = true },
                modifier = Modifier.weight(1f)
            ) { Text(tr("Duplicate", "Дублировать"), maxLines = 1, fontSize = 12.sp) }
        }
        Text(
            tr("Deleting all profiles is allowed; the app can start with none.",
               "Удалить все профили можно — приложение может работать без профилей."),
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f), fontSize = 11.sp
        )

        // Mode selection
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(tr("Mode:", "Режим:"), color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = editing.mode == "proxy",
                onClick = { persist(editing.copy(mode = "proxy")) },
                label = { Text(tr("Proxy", "Прокси")) }
            )
            FilterChip(
                selected = editing.mode == "vpn",
                onClick = { persist(editing.copy(mode = "vpn")) },
                label = { Text("VPN") }
            )
        }
        if (editing.mode == "vpn") {
            Text(tr("VPN mode uses system-wide capture (VpnService). Traffic is routed per your app rules below.", "VPN-режим перехватывает весь трафик (VpnService) по правилам ниже."),
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
        }

        // Routing rules
        Text(tr("Traffic routing:", "Маршрутизация трафика:"), color = MaterialTheme.colorScheme.onSurface)
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            FilterChip(
                selected = editing.routing.mode == "all",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "all"))) },
                label = { Text(tr("All apps", "Все приложения")) }
            )
            FilterChip(
                selected = editing.routing.mode == "allow",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "allow"))) },
                label = { Text(tr("Allow list", "Белый список")) }
            )
            FilterChip(
                selected = editing.routing.mode == "block",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "block"))) },
                label = { Text(tr("Block list", "Чёрный список")) }
            )
        }

        val activeRules = when (editing.routing.mode) {
            "allow" -> editing.routing.allowedApps
            "block" -> editing.routing.blockedApps
            else -> emptyList()
        }
        if (editing.routing.mode == "allow" || editing.routing.mode == "block") {
            Text(
                if (editing.routing.mode == "allow")
                    tr("Apps sent through the tunnel:", "Приложения через туннель:")
                else tr("Apps using direct connection:", "Приложения напрямую:"),
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp
            )
            Button(onClick = {
                pickerList = editing.routing.mode
                showAppPicker = true
            }) { Text(tr("Add app", "Добавить приложение")) }
            activeRules.forEach { rule ->
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("${rule.appName} (${rule.packageName})", Modifier.weight(1f),
                         color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                    SmallButton(tr("Remove", "Удалить")) {
                        val updatedRules = activeRules.filterNot { it.packageName == rule.packageName }
                        val newRouting = if (editing.routing.mode == "allow")
                            editing.routing.copy(allowedApps = updatedRules)
                        else
                            editing.routing.copy(blockedApps = updatedRules)
                        persist(editing.copy(routing = newRouting))
                    }
                }
            }
        }

        Divider()
        Text(tr("Changes apply after Stop/Start.", "Изменения применяются после перезапуска."),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
    }

    if (showNameDialog) {
        var name by remember { mutableStateOf(if (dialogKind == "rename") editing.name else "") }
        AlertDialog(
            onDismissRequest = { showNameDialog = false },
            title = { Text(if (dialogKind == "new") "New profile" else if (dialogKind == "rename") "Rename profile" else "Duplicate profile") },
            text = {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    label = { Text("Profile name") },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        cursorColor = MaterialTheme.colorScheme.primary,
                    )
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val finalName = name.trim().ifEmpty { "Profile" }
                    when (dialogKind) {
                        "new" -> {
                            val p = VpnProfile(name = finalName)
                            configManager.addProfile(p)
                            configManager.selectProfile(p.id)
                            editing = p
                            profiles = configManager.loadProfiles()
                        }
                        "rename" -> persist(editing.copy(name = finalName))
                        "duplicate" -> {
                            val p = editing.copy(id = java.util.UUID.randomUUID().toString(), name = finalName)
                            configManager.addProfile(p)
                            configManager.selectProfile(p.id)
                            editing = p
                            profiles = configManager.loadProfiles()
                        }
                    }
                    showNameDialog = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { showNameDialog = false }) { Text(tr("Cancel", "Отмена")) } }
        )
    }

    if (showAppPicker) {
        AppPickerDialog(
            apps = installedApps,
            onDismiss = { showAppPicker = false },
            onPick = { rule ->
                val list = if (pickerList == "allow") editing.routing.allowedApps else editing.routing.blockedApps
                if (list.none { it.packageName == rule.packageName }) {
                    val newRules = list + rule
                    val newRouting = if (pickerList == "allow")
                        editing.routing.copy(allowedApps = newRules)
                    else
                        editing.routing.copy(blockedApps = newRules)
                    persist(editing.copy(routing = newRouting))
                }
                showAppPicker = false
            }
        )
    }
}

fun getInstalledApps(context: Context): List<AppRule> {
    val pm = context.packageManager
    return try {
        pm.getInstalledApplications(0).mapNotNull { ai ->
            val label = try { pm.getApplicationLabel(ai).toString() } catch (_: Exception) { ai.packageName }
            val isSystem = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM != 0) ||
                (ai.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0)
            AppRule(ai.packageName, label, isSystem)
        }.sortedBy { it.appName.lowercase() }
    } catch (_: Exception) {
        emptyList()
    }
}

@Composable
fun AppPickerDialog(apps: List<AppRule>, onDismiss: () -> Unit, onPick: (AppRule) -> Unit) {
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    // Без remember {} с ключами: просто пересчитываем при каждом состоянии,
    // иначе видимость привязалась бы к первому значению showSystem.
    val visible = if (showSystem) apps else apps.filter { !it.system }
    val filtered = remember(query, visible) {
        if (query.isBlank()) visible else visible.filter {
            it.appName.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(tr("Select app", "Выбрать приложение")) },
        text = {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = showSystem, onCheckedChange = { showSystem = it })
                    Text(tr("Show system apps", "Показывать системные приложения"), color = MaterialTheme.colorScheme.onSurface)
                }
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    label = { Text(tr("Search", "Поиск")) },
                    colors = OutlinedTextFieldDefaults.colors(cursorColor = MaterialTheme.colorScheme.primary)
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn(modifier = Modifier.height(400.dp)) {
                    itemsIndexed(filtered) { _, app ->
                        TextButton(onClick = { onPick(app) }, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.Start) {
                                Text(app.appName, color = MaterialTheme.colorScheme.onSurface)
                                Text(app.packageName, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f), fontSize = 11.sp)
                            }
                        }
                        Divider()
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text(tr("Cancel", "Отмена")) } }
    )
}

// ── Raw JSON config tab ───────────────────────────────────────────────

@Composable
fun RawConfigTab(configManager: ConfigManager, embedded: Boolean = false) {
    var raw by remember { mutableStateOf(configManager.loadRaw()) }
    var cooldown by remember { mutableStateOf(configManager.load().urlCooldownSeconds.toString()) }
    var failLimit by remember { mutableStateOf(configManager.load().urlFailLimit.toString()) }
    var status by remember { mutableStateOf("") }

    fun applyNumber(update: (ProxyConfig) -> ProxyConfig) {
        configManager.save(update(configManager.load()))
        raw = configManager.loadRaw()
    }

    Column(
        modifier = if (embedded) {
            Modifier.fillMaxWidth()
        } else {
            Modifier.fillMaxSize().padding(16.dp)
        },
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(tr("Edit full config (JSON). Server block is ignored.", "Редактирование полного JSON. Блок server игнорируется."),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
             fontSize = 13.sp)

        Text(tr("URL quarantine", "Карантин URL"),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f),
             fontSize = 13.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            ConfigTextField(
                label = "Quarantine (s)",
                value = cooldown,
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { text ->
                cooldown = text
                text.toIntOrNull()?.takeIf { it > 0 }?.let { v ->
                    applyNumber { cfg -> cfg.copy(urlCooldownSeconds = v) }
                }
            }
            ConfigTextField(
                label = "Fail limit",
                value = failLimit,
                modifier = Modifier.weight(1f),
                keyboardType = KeyboardType.Number
            ) { text ->
                failLimit = text
                text.toIntOrNull()?.takeIf { it > 0 }?.let { v ->
                    applyNumber { cfg -> cfg.copy(urlFailLimit = v) }
                }
            }
        }
        Text(tr("After this many consecutive errors a URL is quarantined for the given time.", "После стольких ошибок подряд URL уходит в карантин на указанное время."),
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.45f),
             fontSize = 11.sp)

        OutlinedTextField(
            value = raw,
            onValueChange = { raw = it },
            modifier = if (embedded) {
                Modifier.fillMaxWidth().height(320.dp)
            } else {
                Modifier.weight(1f).fillMaxWidth()
            },
            textStyle = LocalTextStyle.current.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurface
            ),
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = MaterialTheme.colorScheme.primary,
                unfocusedBorderColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f),
                cursorColor = MaterialTheme.colorScheme.primary,
            )
        )

        if (status.isNotEmpty()) {
            Text(status, color = if (status.startsWith("OK")) Color(0xFF4CAF50) else Color(0xFFEF5350),
                 fontSize = 13.sp)
        }

        Button(
            onClick = {
                configManager.parseRaw(raw)?.let {
                    configManager.saveRaw(raw)
                    configManager.save(it)
                    cooldown = it.urlCooldownSeconds.toString()
                    failLimit = it.urlFailLimit.toString()
                    raw = configManager.loadRaw()
                    status = "OK – config saved"
                } ?: run { status = "Invalid JSON" }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(tr("Save Config", "Сохранить конфиг"))
        }
    }
}

// ── Log tab ───────────────────────────────────────────────────────────

@Composable
fun LogTab(logs: SnapshotStateList<LogEntry>, autoScroll: Boolean, onAutoScrollChange: (Boolean) -> Unit) {
    val listState = rememberLazyListState()
    val selectedIds = remember { mutableStateListOf<Long>() }
    val context = LocalContext.current
    val evenColor = MaterialTheme.colorScheme.surface
    val oddColor = Color(0xFF0F0F23)
    val selectedColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)

    LaunchedEffect(logs.size, autoScroll) {
        if (autoScroll && logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    // Scroll to bottom immediately when auto-scroll is re-enabled
    LaunchedEffect(autoScroll) {
        if (autoScroll && logs.isNotEmpty()) {
            listState.animateScrollToItem(logs.size - 1)
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // Action bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 8.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(tr("Auto-scroll:", "Автопрокрутка:"), fontSize = 12.sp,
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
            Checkbox(checked = autoScroll, onCheckedChange = onAutoScrollChange,
                     modifier = Modifier.height(24.dp))
            Spacer(Modifier.weight(1f))
            SmallButton("Copy all") {
                val text = logs.joinToString("\n") { it.text }
                val clip = ClipData.newPlainText("proxy_log", text)
                (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
            }
            SmallButton("Copy sel") {
                val text = logs.filter { it.id in selectedIds }
                    .sortedBy { it.id }.joinToString("\n") { it.text }
                if (text.isNotEmpty()) {
                    val clip = ClipData.newPlainText("proxy_log", text)
                    (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(clip)
                }
            }
            SmallButton("Clear") {
                logs.clear()
                selectedIds.clear()
            }
        }

        // Log list
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 4.dp)
        ) {
            itemsIndexed(logs) { index, entry ->
                val isSelected = entry.id in selectedIds
                val bg = when {
                    isSelected -> selectedColor
                    index % 2 == 0 -> evenColor
                    else -> oddColor
                }
                Text(
                    text = entry.text,
                    color = MaterialTheme.colorScheme.onSurface,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(bg)
                        .pointerInput(entry.id, isSelected) {
                            detectTapGestures(
                                onTap = {
                                    if (entry.id in selectedIds) selectedIds.remove(entry.id)
                                    else selectedIds.add(entry.id)
                                }
                            )
                        }
                        .padding(horizontal = 8.dp, vertical = 1.dp)
                )
            }
        }
    }
}

@Composable
fun SmallButton(text: String, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp),
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.primary.copy(alpha = 0.2f),
            contentColor = Color.White
        )
    ) {
        Text(text, fontSize = 11.sp, color = Color.White)
    }
}

fun startProxy(context: Context) {
    val intent = Intent(context, ProxyService::class.java).apply {
        action = ProxyService.ACTION_START
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(intent)
    } else {
        context.startService(intent)
    }
}

fun stopProxy(context: Context) {
    val intent = Intent(context, ProxyService::class.java).apply {
        action = ProxyService.ACTION_STOP
    }
    context.startService(intent)
}

fun resetUrlErrors(context: Context) {
    if (!ProxyService.isProxyRunning) return
    val intent = Intent(context, ProxyService::class.java).apply {
        action = ProxyService.ACTION_RESET_URL_ERRORS
    }
    context.startService(intent)
}

fun restartProxy(context: Context) {
    if (ProxyService.isProxyRunning) {
        context.startService(Intent(context, ProxyService::class.java).apply {
            action = ProxyService.ACTION_STOP
        })
    }
    Handler(Looper.getMainLooper()).postDelayed({
        val activity = context as? MainActivity
        if (activity != null) activity.startProxyWithVpnCheck() else startProxy(context)
    }, 900)
}
