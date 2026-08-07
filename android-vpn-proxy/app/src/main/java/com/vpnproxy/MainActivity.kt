package com.vpnproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.snapshots.SnapshotStateList
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager

data class LogEntry(val id: Long, val text: String)

class MainActivity : ComponentActivity() {
    private lateinit var configManager: ConfigManager
    private var logSeq = 0L
    private val logs = mutableStateListOf<LogEntry>()
    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.getStringExtra("msg")?.let { msg ->
                logs.add(LogEntry(++logSeq, msg))
                if (logs.size > 500) logs.removeAt(0)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configManager = ConfigManager(this)

        val filter = IntentFilter("com.vpnproxy.LOG")
        ContextCompat.registerReceiver(this, logReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)

        setContent {
            MaterialTheme(
                colorScheme = darkColorScheme(
                    primary = Color(0xFF90CAF9),
                    secondary = Color(0xFF80CBC4),
                    surface = Color(0xFF1A1A2E),
                    background = Color(0xFF0F0F23),
                    onPrimary = Color.Black,
                    onSecondary = Color.Black,
                    onSurface = Color.White,
                    onBackground = Color.White,
                )
            ) {
                MainScreen(configManager, logs)
            }
        }
    }

    override fun onDestroy() {
        unregisterReceiver(logReceiver)
        super.onDestroy()
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(configManager: ConfigManager, logs: SnapshotStateList<LogEntry>) {
    var tab by remember { mutableIntStateOf(0) }
    var isRunning by remember { mutableStateOf(false) }
    var autoScroll by remember { mutableStateOf(true) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Short Polling VPN") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface,
                    titleContentColor = MaterialTheme.colorScheme.onSurface,
                )
            )
        },
        bottomBar = {
            val context = LocalContext.current
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    onClick = {
                        val seq = logs.size.toLong() + 1
                        if (isRunning) {
                            logs.add(LogEntry(seq, "Stopping proxy service..."))
                            stopProxy(context)
                        } else {
                            logs.add(LogEntry(seq, "Start button clicked. Launching service..."))
                            startProxy(context)
                        }
                        isRunning = !isRunning
                    },
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (isRunning) Color(0xFFEF5350)
                        else Color(0xFF4CAF50)
                    )
                ) {
                    Text(if (isRunning) "Stop" else "Start", fontSize = 16.sp)
                }
            }
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            TabRow(selectedTabIndex = tab) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Simple") })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Config") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Log") })
            }
            when (tab) {
                0 -> SimpleConfigTab(configManager)
                1 -> RawConfigTab(configManager)
                2 -> LogTab(logs, autoScroll, { autoScroll = it })
            }
        }
    }
}

// ── Simple config tab ─────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SimpleConfigTab(configManager: ConfigManager) {
    var cfg by remember { mutableStateOf(configManager.load()) }
    val scroll = rememberScrollState()

    fun save(c: ProxyConfig) {
        cfg = c
        configManager.save(c)
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll)
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        ConfigTextField("Server URL", cfg.serverUrl) { save(cfg.copy(serverUrl = it)) }
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
            Text("Method:", color = MaterialTheme.colorScheme.onSurface)
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
            Text("Data in:", color = MaterialTheme.colorScheme.onSurface)
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
            Text("Verify TLS:", color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.verifyTls,
                onCheckedChange = { save(cfg.copy(verifyTls = it)) })
        }

        Text("Idle timeout:",
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Enabled:", color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.idleTimeoutEnabled,
                onCheckedChange = { save(cfg.copy(idleTimeoutEnabled = it)) })
            Spacer(Modifier.weight(1f))
            ConfigTextField("Timeout (s)", cfg.idleTimeoutSeconds.toString(),
                modifier = Modifier.width(120.dp).weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(idleTimeoutSeconds = v)) } }
        }
    }
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

// ── Raw JSON config tab ───────────────────────────────────────────────

@Composable
fun RawConfigTab(configManager: ConfigManager) {
    var raw by remember { mutableStateOf(configManager.loadRaw()) }
    var status by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text("Edit full config (JSON). Server block is ignored.",
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
             fontSize = 13.sp)

        OutlinedTextField(
            value = raw,
            onValueChange = { raw = it },
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth(),
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
                    status = "OK – config saved"
                } ?: run { status = "Invalid JSON" }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Save Config")
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
            Text("Auto-scroll:", fontSize = 12.sp,
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
