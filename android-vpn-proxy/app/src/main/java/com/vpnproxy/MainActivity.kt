package com.vpnproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import android.net.VpnService
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
import java.util.UUID

data class LogEntry(val id: Long, val text: String)

class MainActivity : ComponentActivity() {
    private lateinit var configManager: ConfigManager
    private var logSeq = 0L
    private val logs = mutableStateListOf<LogEntry>()
    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            intent?.getStringExtra("msg")?.let { msg ->
                logs.add(LogEntry(++logSeq, msg))
                if (logs.size > 3000) logs.removeAt(0)
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
        val profile = configManager.getActiveProfile()
        if (profile.mode == "vpn") {
            val intent = VpnService.prepare(this)
            if (intent != null) {
                vpnConsent.launch(intent)
                return
            }
        }
        startProxy(this)
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
                            val activity = context as? MainActivity
                            if (activity != null) {
                                activity.startProxyWithVpnCheck()
                            } else {
                                startProxy(context)
                            }
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
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("Profiles") })
                Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Config") })
                Tab(selected = tab == 3, onClick = { tab = 3 }, text = { Text("Log") })
            }
            when (tab) {
                0 -> SimpleConfigTab(configManager)
                1 -> ProfilesTab(configManager)
                2 -> RawConfigTab(configManager)
                3 -> LogTab(logs, autoScroll, { autoScroll = it })
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

        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Log level:", color = MaterialTheme.colorScheme.onSurface)
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

        Text("DNS relay:",
             color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f))
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Enabled:", color = MaterialTheme.colorScheme.onSurface)
            Switch(checked = cfg.dnsRelayEnabled,
                onCheckedChange = { save(cfg.copy(dnsRelayEnabled = it)) })
            Spacer(Modifier.weight(1f))
            ConfigTextField("Port", cfg.dnsBindPort.toString(),
                modifier = Modifier.width(120.dp).weight(1f),
                keyboardType = KeyboardType.Number
            ) { it.toIntOrNull()?.let { v -> save(cfg.copy(dnsBindPort = v)) } }
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

// ── Profiles tab ──────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesTab(configManager: ConfigManager) {
    var profiles by remember { mutableStateOf(configManager.loadProfiles()) }
    var activeId by remember { mutableStateOf(configManager.getActiveProfile().id) }
    var editing by remember { mutableStateOf(configManager.getActiveProfile()) }
    var showNameDialog by remember { mutableStateOf(false) }
    var dialogKind by remember { mutableStateOf("new") } // new | rename | duplicate
    val appContext = LocalContext.current
    val installedApps = remember { getInstalledApps(appContext) }
    var showAppPicker by remember { mutableStateOf(false) }
    var pickerList by remember { mutableStateOf("allow") } // allow | block
    var pendingDelete by remember { mutableStateOf<VpnProfile?>(null) }

    fun refresh() {
        profiles = configManager.loadProfiles()
        activeId = configManager.getActiveProfile().id
        editing = configManager.getActiveProfile()
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
        Text("Profiles", style = MaterialTheme.typography.titleMedium,
             color = MaterialTheme.colorScheme.onSurface)
        Text("Each profile stores mode, connection settings and routing. Switch, then Stop/Start to apply.",
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
                        Text("ACTIVE", color = MaterialTheme.colorScheme.primary, fontSize = 11.sp)
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
                title = { Text("Delete profile") },
                text = { Text("Delete \"${doomed.name}\"? This cannot be undone.") },
                confirmButton = {
                    TextButton(onClick = {
                        configManager.deleteProfile(doomed.id)
                        pendingDelete = null
                        refresh()
                    }) { Text("Delete") }
                },
                dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text("Cancel") } }
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
            ) { Text("New") }
            Button(
                onClick = { dialogKind = "rename"; showNameDialog = true },
                modifier = Modifier.weight(1f)
            ) { Text("Rename") }
            Button(
                onClick = { dialogKind = "duplicate"; showNameDialog = true },
                modifier = Modifier.weight(1f)
            ) { Text("Duplicate") }
        }

        // Mode selection
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Mode:", color = MaterialTheme.colorScheme.onSurface)
            FilterChip(
                selected = editing.mode == "proxy",
                onClick = { persist(editing.copy(mode = "proxy")) },
                label = { Text("Proxy") }
            )
            FilterChip(
                selected = editing.mode == "vpn",
                onClick = { persist(editing.copy(mode = "vpn")) },
                label = { Text("VPN") }
            )
        }
        if (editing.mode == "vpn") {
            Text("VPN mode uses system-wide capture (VpnService). Traffic is routed per your app rules below.",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
        }

        // Routing rules
        Text("Traffic routing:", color = MaterialTheme.colorScheme.onSurface)
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            FilterChip(
                selected = editing.routing.mode == "all",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "all"))) },
                label = { Text("All apps") }
            )
            FilterChip(
                selected = editing.routing.mode == "allow",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "allow"))) },
                label = { Text("Allow list") }
            )
            FilterChip(
                selected = editing.routing.mode == "block",
                onClick = { persist(editing.copy(routing = editing.routing.copy(mode = "block"))) },
                label = { Text("Block list") }
            )
        }

        val activeRules = when (editing.routing.mode) {
            "allow" -> editing.routing.allowedApps
            "block" -> editing.routing.blockedApps
            else -> emptyList()
        }
        if (editing.routing.mode == "allow" || editing.routing.mode == "block") {
            Text(if (editing.routing.mode == "allow") "Apps sent through the tunnel:" else "Apps using direct connection:",
                 color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f), fontSize = 12.sp)
            Button(onClick = {
                pickerList = editing.routing.mode
                showAppPicker = true
            }) { Text("Add app") }
            activeRules.forEach { rule ->
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text("${rule.appName} (${rule.packageName})", Modifier.weight(1f),
                         color = MaterialTheme.colorScheme.onSurface, fontSize = 13.sp)
                    SmallButton("Remove") {
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
        Text("Changes apply after Stop/Start.",
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
                            editing = p
                            profiles = configManager.loadProfiles()
                        }
                        "rename" -> persist(editing.copy(name = finalName))
                        "duplicate" -> {
                            val p = editing.copy(id = java.util.UUID.randomUUID().toString(), name = finalName)
                            configManager.addProfile(p)
                            editing = p
                            profiles = configManager.loadProfiles()
                        }
                    }
                    showNameDialog = false
                }) { Text("OK") }
            },
            dismissButton = { TextButton(onClick = { showNameDialog = false }) { Text("Cancel") } }
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
            AppRule(ai.packageName, label)
        }.sortedBy { it.appName.lowercase() }
    } catch (_: Exception) {
        emptyList()
    }
}

@Composable
fun AppPickerDialog(apps: List<AppRule>, onDismiss: () -> Unit, onPick: (AppRule) -> Unit) {
    var query by remember { mutableStateOf("") }
    val filtered = remember(query, apps) {
        if (query.isBlank()) apps else apps.filter {
            it.appName.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true)
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Select app") },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    label = { Text("Search") },
                    colors = OutlinedTextFieldDefaults.colors(cursorColor = MaterialTheme.colorScheme.primary)
                )
                Spacer(Modifier.height(8.dp))
                LazyColumn(modifier = Modifier.height(400.dp)) {
                    itemsIndexed(filtered) { _, app ->
                        TextButton(onClick = { onPick(app) }, modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.align(Alignment.CenterVertically)) {
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
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } }
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
