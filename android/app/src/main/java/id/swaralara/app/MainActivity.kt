package id.swaralara.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import id.swaralara.app.backend.*
import id.swaralara.core.*
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.catch
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val core = CoreRuntime.get(applicationContext)
        window.statusBarColor = android.graphics.Color.rgb(250, 244, 252)
        window.navigationBarColor = android.graphics.Color.rgb(84, 32, 68)
        window.decorView.systemUiVisibility = android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR
        setContent {
            SwaraTheme {
                Surface(Modifier.fillMaxSize(), color = Page) { ConnectedScreen(core, this) }
            }
        }
    }

    override fun onStop() {
        CoreRuntime.get(applicationContext).onHostBackgrounded()
        super.onStop()
    }
}

@Composable
private fun ConnectedScreen(core: CoreRuntime, context: android.content.Context) {
    val scope = rememberCoroutineScope()
    val url = BuildConfig.SUPABASE_URL.trimEnd('/')
    val sessions = remember { SessionStore(context, url) }
    val client = remember {
        if (url.isBlank() || BuildConfig.SUPABASE_PUBLISHABLE_KEY.isBlank()) null
        else
            runCatching { CloudClient(url, BuildConfig.SUPABASE_PUBLISHABLE_KEY, sessions) }
                .getOrNull()
    }
    var session by remember { mutableStateOf(sessions.load()) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf("") }
    var links by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var policy by remember { mutableStateOf<CloudCapturePolicy?>(null) }
    var status by remember { mutableStateOf("") }
    var working by remember { mutableStateOf(false) }

    // M3: inbox persetujuan pemegang
    var accessRequests by remember { mutableStateOf<List<KeyAccessRequest>>(emptyList()) }
    // M3: requestId aktif per recordingId (untuk pemulihan DEK)
    var activeRequestIds by remember { mutableStateOf<Map<UUID, UUID>>(emptyMap()) }

    val recordingFlow =
        remember(core) {
            core.vault.observeRecordings().catch {
                status = "Brankas belum dapat dibaca. Data lokal dipertahankan."
                emit(emptyList())
            }
        }
    val recordings by recordingFlow.collectAsStateWithLifecycle(emptyList())
    val capture by core.recorder.state.collectAsStateWithLifecycle()

    fun action(block: suspend () -> Unit) {
        if (working) return
        working = true
        scope.launch {
            try {
                core.awaitReady()
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: CloudError) {
                status = "Backend: ${e.code} (${e.status}). Data lokal dipertahankan."
            } catch (_: Exception) {
                status =
                    "Operasi belum berhasil. Periksa konfigurasi, koneksi, identitas perangkat, dan izin."
            } finally {
                working = false
            }
        }
    }

    suspend fun refresh() {
        val a = client!!.links()
        links = (0 until a.length()).map { a.getJSONObject(it) }
    }

    // M3: LaunchedEffect — trigger workers saat login & rekaman berubah
    LaunchedEffect(recordings, session?.userId) {
        if (client != null && session != null) {
            recordings
                .filter {
                    it.capture in setOf(CaptureState.SEALED, CaptureState.INTERRUPTED) &&
                        it.recovery == RecoveryState.DEGRADED &&
                        it.sync == SyncState.QUEUED
                }
                .forEach { UploadWorker.enqueue(context, it.id) }

            // M3: enqueue EnvelopeWorker untuk rekaman yang sudah SYNCED & siap distribusi
            recordings
                .filter {
                    it.sync == SyncState.SYNCED && it.recovery == RecoveryState.ENVELOPES_QUEUED
                }
                .forEach { EnvelopeWorker.enqueue(context, it.id) }

            // M3: poll RecoveryWorker sekali saat login (KEEP — tidak duplikat)
            RecoveryWorker.enqueueOnce(context)
        }
    }

    var tabName by rememberSaveable { mutableStateOf(Destination.HOME.name) }
    val tab = Destination.valueOf(tabName)
    var recordingId by rememberSaveable { mutableStateOf<String?>(null) }
    var requestId by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingLink by remember { mutableStateOf<JSONObject?>(null) }
    var auditText by remember { mutableStateOf<String?>(null) }
    val playback by core.playback.state.collectAsStateWithLifecycle()
    val selectedRecording = recordings.firstOrNull { it.id.toString() == recordingId }
    val selectedRequest = accessRequests.firstOrNull { it.requestId.toString() == requestId }
    val snackbar = remember { SnackbarHostState() }
    val pageScroll = rememberScrollState()
    val clipboard = LocalClipboardManager.current
    LaunchedEffect(tabName, recordingId, requestId) { pageScroll.scrollTo(0) }
    LaunchedEffect(tabName, session?.userId) {
        if (client != null && session != null) {
            if (tab == Destination.DEVICES) action { refresh() }
            if (tab == Destination.ACCESS) action { accessRequests = client.getAccessRequests() }
        }
    }
    LaunchedEffect(status) {
        if (status.isNotBlank()) {
            snackbar.showSnackbar(status)
            status = ""
        }
    }
    LaunchedEffect(capture.errorCode) {
        capture.errorCode?.let { status = "Perekaman belum berhasil: $it" }
    }
    BackHandler(enabled = recordingId != null || requestId != null || tab != Destination.HOME) {
        if (recordingId != null) {
            recordingId = null
            scope.launch { core.playback.release() }
        } else if (requestId != null) requestId = null else tabName = Destination.HOME.name
    }
    fun requireAccount(block: suspend () -> Unit) {
        if (client == null || session == null) {
            status = "Masuk ke akun untuk menghubungkan perangkat dan mengelola akses."
            tabName = Destination.SETTINGS.name
        } else action(block)
    }
    fun decide(req: KeyAccessRequest, approved: Boolean) {
        requireAccount {
            if (approved) {
                val release = core.keyExchange.approveAndRelease(req, userApproved = true)
                client!!.submitDecision(req, core.identity, release)
            } else client!!.submitDecision(req, core.identity, null)
            accessRequests = accessRequests.filterNot { it.requestId == req.requestId }
            requestId = null
            status = if (approved) "Persetujuan dikirim." else "Permintaan ditolak."
        }
    }
    if (capture.busy) {
        RecordingScreen(capture) {
            scope.launch {
                try { core.recorder.stop() }
                catch (e: CancellationException) { throw e }
                catch (_: Exception) { status = "Gunakan tombol berhenti pada notifikasi jika rekaman belum berhenti." }
            }
        }
    } else
        Scaffold(
            containerColor = Page,
            snackbarHost = { SnackbarHost(snackbar) },
            bottomBar = {
                SwaraBottomBar(tab) {
                    if (recordingId != null) scope.launch { core.playback.release() }
                    recordingId = null
                    requestId = null
                    tabName = it.name
                }
            },
        ) { insets ->
            Column(
                Modifier.fillMaxSize()
                    .padding(insets)
                    .verticalScroll(pageScroll)
                    .padding(horizontal = 18.dp)
            ) {
                when {
                    selectedRecording != null -> {
                        val r = selectedRecording
                        PageHeading(
                            "Rekaman",
                            back = {
                                recordingId = null
                                scope.launch { core.playback.release() }
                            },
                        )
                        RecordingDetail(
                            r,
                            playback,
                            working,
                            inspect = { action { status = core.vault.inspect(r.id).message } },
                            prepare = {
                                action {
                                    if (!core.playback.prepare(r.id))
                                        status = "Rekaman belum dapat diputar."
                                }
                            },
                            audit = {
                                auditText =
                                    "ID: ${r.id}\n${r.segmentCount} segmen · ${r.frames} frame\nIntegritas: ${r.integrity}\nSinkronisasi: ${r.sync}\nPemulihan: ${r.recovery}"
                            },
                            play = { action { core.playback.play() } },
                            pause = { action { core.playback.pause() } },
                            close = { action { core.playback.release() } },
                        )
                        if (r.recovery == RecoveryState.DEGRADED)
                            Pill(
                                "Unggah / coba lagi",
                                {
                                    requireAccount {
                                        UploadWorker.enqueue(context, r.id)
                                        status = "Unggah dijadwalkan."
                                    }
                                },
                                Modifier.padding(top = 20.dp),
                                enabled = !working,
                            )
                        if (
                            r.recovery in
                                setOf(
                                    RecoveryState.ENVELOPES_QUEUED,
                                    RecoveryState.ENVELOPES_UPLOADED,
                                )
                        )
                            Pill(
                                "Distribusi kunci",
                                {
                                    requireAccount {
                                        EnvelopeWorker.enqueue(context, r.id)
                                        status = "Distribusi kunci dijadwalkan."
                                    }
                                },
                                Modifier.padding(top = 20.dp),
                            )
                        if (r.recovery == RecoveryState.HOLDERS_ACKNOWLEDGED) {
                            val existing = activeRequestIds[r.id]
                            Pill(
                                if (existing == null) "Minta pemulihan" else "Pulihkan rekaman",
                                {
                                    requireAccount {
                                        if (existing == null) {
                                            val request =
                                                core.keyExchange.createRequest(
                                                    core.keyExchange.exportPolicy(r.id)
                                                )
                                            activeRequestIds =
                                                activeRequestIds +
                                                    (r.id to client!!.createAccessRequest(request))
                                            status = "Permintaan pemulihan dibuat."
                                        } else {
                                            val auth =
                                                core.keyExchange.authorizeReleasesRead(existing)
                                            status =
                                                core.keyExchange
                                                    .recover(
                                                        existing,
                                                        client!!.getReleases(existing, auth),
                                                    )
                                                    .message
                                        }
                                    }
                                },
                                Modifier.padding(top = 20.dp),
                                enabled = !working,
                            )
                        }
                    }
                    selectedRequest != null -> {
                        val req = selectedRequest
                        PageHeading("Permintaan Akses", back = { requestId = null })
                        SwaraCard {
                            Text(
                                "Menunggu persetujuan",
                                color = Plum,
                                fontSize = 21.sp,
                                fontWeight = FontWeight.SemiBold,
                            )
                            Spacer(Modifier.height(2.dp))
                            Text("Rekaman", color = Muted)
                            Text(
                                recordings
                                    .firstOrNull { it.id == req.recordingId }
                                    ?.let(::recordingName) ?: req.recordingId.toString().take(12)
                            )
                            Text("Peminta", color = Muted)
                            Text("Perangkat ${req.requesterDeviceId.toString().take(12)}")
                            Text("Kedaluwarsa", color = Muted)
                            Text(
                                if (req.expiresAt <= System.currentTimeMillis()) "Kedaluwarsa"
                                else "${((req.expiresAt-System.currentTimeMillis())/60000+1)} menit"
                            )
                        }
                        Spacer(Modifier.height(30.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Pill(
                                "Setujui",
                                { decide(req, true) },
                                Modifier.weight(1f),
                                filled = true,
                                enabled = !working && req.expiresAt > System.currentTimeMillis(),
                            )
                            Pill(
                                "Tolak",
                                { decide(req, false) },
                                Modifier.weight(1f),
                                filled = true,
                                pink = true,
                                enabled = !working,
                            )
                        }
                        Text(
                            "Persetujuan tidak membuka\nkunci pada server.",
                            Modifier.fillMaxWidth().padding(top = 50.dp),
                            color = Muted,
                            fontSize = 16.sp,
                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                        )
                    }
                    tab == Destination.HOME -> {
                        PageHeading("SwaraLara")
                        CaptureCard(core, policy) { status = it }
                        Text(
                            "Terbaru",
                            Modifier.padding(top = 18.dp, bottom = 12.dp),
                            fontSize = 18.sp,
                        )
                        if (recordings.isEmpty())
                            EmptyState(
                                "Belum ada rekaman",
                                "Rekaman yang kamu buat akan muncul di sini.",
                                "mic",
                            )
                        recordings.take(3).forEach { r ->
                            RecordingRow(r) {
                                tabName = Destination.VAULT.name
                                recordingId = r.id.toString()
                            }
                            Spacer(Modifier.height(10.dp))
                        }
                    }
                    tab == Destination.VAULT -> {
                        PageHeading("Brankas")
                        if (recordings.isEmpty())
                            EmptyState(
                                "Brankas masih kosong",
                                "Mulai rekaman dari Beranda.",
                                "lock",
                            )
                        recordings.forEach { r ->
                            RecordingRow(r) { recordingId = r.id.toString() }
                            Spacer(Modifier.height(12.dp))
                        }
                    }
                    tab == Destination.DEVICES -> {
                        PageHeading("Perangkat")
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Pill(
                                "Daftarkan",
                                {
                                    requireAccount {
                                        client!!.register(core.identity.publicIdentity())
                                        refresh()
                                        status = "Perangkat terdaftar."
                                    }
                                },
                                filled = true,
                                enabled = !working,
                            )
                            Pill(
                                "Undang",
                                {
                                    requireAccount {
                                        val result =
                                            client!!.api(
                                                "/trust/invitations",
                                                "POST",
                                                JSONObject()
                                                    .put(
                                                        "deviceId",
                                                        core.identity.publicIdentity().deviceId,
                                                    ),
                                            ) as JSONObject
                                        invitation = result.getString("token")
                                    }
                                },
                                enabled = !working,
                            )
                        }
                        if (invitation.isNotBlank()) {
                            Spacer(Modifier.height(16.dp))
                            SwaraCard {
                                Text("Undangan · berlaku 15 menit", color = Plum)
                                SelectionContainer { Text(invitation) }
                                Pill(
                                    "Salin token",
                                    {
                                        clipboard.setText(AnnotatedString(invitation))
                                        status = "Token disalin."
                                    },
                                )
                            }
                        }
                        Spacer(Modifier.height(22.dp))
                        OutlinedTextField(
                            token,
                            { token = it },
                            Modifier.fillMaxWidth(),
                            label = { Text("Token") },
                            singleLine = true,
                            trailingIcon = {
                                IconButton(
                                    onClick = {
                                        clipboard.setText(AnnotatedString(token))
                                        status = "Token disalin."
                                    },
                                    enabled = token.isNotBlank(),
                                ) {
                                    SwaraIcon("copy")
                                }
                            },
                        )
                        Spacer(Modifier.height(10.dp))
                        Pill(
                            "Hubungkan",
                            {
                                requireAccount {
                                    client!!.api(
                                        "/trust/accept",
                                        "POST",
                                        JSONObject()
                                            .put("token", token)
                                            .put(
                                                "deviceId",
                                                core.identity.publicIdentity().deviceId,
                                            ),
                                    )
                                    token = ""
                                    refresh()
                                    status =
                                        "Cocokkan fingerprint kedua perangkat sebelum konfirmasi."
                                }
                            },
                            Modifier.fillMaxWidth(),
                            filled = true,
                            enabled = !working && token.isNotBlank(),
                        )
                        Spacer(Modifier.height(24.dp))
                        links.forEach { link ->
                            val owner = link.getJSONObject("ownerDevice")
                            val holder = link.getJSONObject("holderDevice")
                            SwaraCard {
                                Row(
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                                ) {
                                    SwaraIcon("devices")
                                    Text("holder ${link.getString("state")}")
                                }
                                Text(holder.getString("id").take(16))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Pill(
                                        "Salin",
                                        {
                                            clipboard.setText(
                                                AnnotatedString(
                                                    "Pemilik: ${owner.getString("signing_fingerprint")} / ${owner.getString("hpke_fingerprint")}\nPemegang: ${holder.getString("signing_fingerprint")} / ${holder.getString("hpke_fingerprint")}"
                                                )
                                            )
                                            status = "Fingerprint disalin."
                                        },
                                    )
                                    Pill(
                                        "Konfirmasi",
                                        {
                                            auditText =
                                                "Fingerprint pemilik\n${owner.getString("signing_fingerprint")}\n${owner.getString("hpke_fingerprint")}\n\nFingerprint pemegang\n${holder.getString("signing_fingerprint")}\n${holder.getString("hpke_fingerprint")}"
                                            pendingLink = link
                                        },
                                        enabled = !working && !sessions.pinned(link),
                                    )
                                }
                                if (
                                    link.getString("owner_user_id") == session?.userId.toString() &&
                                        link.getString("state") == "active" &&
                                        sessions.pinned(link)
                                ) {
                                    Pill(
                                        "Gunakan untuk rekaman",
                                        {
                                            action {
                                                val own = core.identity.publicIdentity()
                                                policy =
                                                    CloudCapturePolicy(
                                                        session!!.userId,
                                                        own.deviceId,
                                                        "owner_required_2of2",
                                                        listOf(
                                                            CloudMember(
                                                                1,
                                                                session!!.userId,
                                                                own.deviceId,
                                                                own.hpkeFingerprint,
                                                                own.signingFingerprint,
                                                            ),
                                                            CloudMember(
                                                                2,
                                                                UUID.fromString(
                                                                    link.getString("holder_user_id")
                                                                ),
                                                                UUID.fromString(
                                                                    holder.getString("id")
                                                                ),
                                                                holder.getString(
                                                                    "hpke_fingerprint"
                                                                ),
                                                                holder.getString(
                                                                    "signing_fingerprint"
                                                                ),
                                                            ),
                                                        ),
                                                    )
                                                status =
                                                    "Perangkat terpercaya dipilih untuk rekaman baru."
                                            }
                                        },
                                        enabled = !working,
                                    )
                                }
                            }
                            Spacer(Modifier.height(12.dp))
                        }
                        if (links.isEmpty())
                            EmptyState(
                                "Belum ada perangkat",
                                "Daftarkan perangkat atau hubungkan dengan token undangan.",
                                "devices",
                            )
                    }
                    tab == Destination.ACCESS -> {
                        PageHeading(
                            "Akses",
                            trailing = {
                                TextButton(
                                    onClick = {
                                        requireAccount {
                                            accessRequests = client!!.getAccessRequests()
                                            status = "Permintaan akses dimuat."
                                        }
                                    },
                                    enabled = !working,
                                ) {
                                    Text("Muat ulang", fontSize = 12.sp)
                                }
                            },
                        )
                        if (accessRequests.isEmpty())
                            EmptyState(
                                "Belum ada permintaan",
                                "Permintaan akses rekaman akan muncul di sini.",
                                "inbox",
                            )
                        accessRequests.forEach { req ->
                            SwaraCard(Modifier.clickable { requestId = req.requestId.toString() }) {
                                Row(
                                    Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Text("Pending", fontWeight = FontWeight.Medium)
                                    Text(
                                        java.text
                                            .SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US)
                                            .format(java.util.Date(req.expiresAt)),
                                        fontSize = 10.sp,
                                        color = Muted,
                                    )
                                }
                                Text(
                                    "Pendamping terpercaya · ${req.requesterDeviceId.toString().take(8)}…",
                                    fontSize = 13.sp,
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Badge("threshold")
                                    Badge("device-${req.requesterDeviceId.toString().take(4)}")
                                }
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Pill(
                                        "Tolak",
                                        { decide(req, false) },
                                        filled = true,
                                        enabled = !working,
                                    )
                                    Pill(
                                        "Setujui",
                                        { requestId = req.requestId.toString() },
                                        enabled = !working,
                                    )
                                }
                            }
                            Spacer(Modifier.height(12.dp))
                        }
                    }
                    tab == Destination.SETTINGS -> {
                        PageHeading("Pengaturan")
                        SwaraCard {
                            Text("Akun", fontSize = 20.sp, color = Plum)
                            if (client == null) {
                                Text(
                                    "Rekam dan simpan di perangkat ini. Layanan akun belum tersedia.",
                                    color = Muted,
                                )
                            } else if (session == null) {
                                Text(
                                    "Masuk untuk menghubungkan perangkat terpercaya dan mengelola akses.",
                                    color = Muted,
                                    fontSize = 14.sp,
                                )
                                OutlinedTextField(
                                    email,
                                    { email = it },
                                    Modifier.fillMaxWidth(),
                                    label = { Text("Email") },
                                    singleLine = true,
                                )
                                OutlinedTextField(
                                    password,
                                    { password = it },
                                    Modifier.fillMaxWidth(),
                                    label = { Text("Kata sandi") },
                                    singleLine = true,
                                    visualTransformation = PasswordVisualTransformation(),
                                )
                                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                    Pill(
                                        "Masuk",
                                        {
                                            action {
                                                session = client.login(email, password)
                                                password = ""
                                                client.register(core.identity.publicIdentity())
                                                refresh()
                                                status = "Berhasil masuk."
                                            }
                                        },
                                        filled = true,
                                        enabled = !working,
                                    )
                                    Pill(
                                        "Daftar",
                                        {
                                            action {
                                                session = client.signup(email, password)
                                                password = ""
                                                status =
                                                    "Akun dibuat. Periksa email untuk konfirmasi."
                                            }
                                        },
                                        enabled = !working,
                                    )
                                }
                            } else {
                                Text(session!!.userId.toString(), fontSize = 13.sp)
                                Pill(
                                    "Keluar",
                                    {
                                        policy = null
                                        sessions.clear()
                                        session = null
                                        links = emptyList()
                                        invitation = ""
                                        accessRequests = emptyList()
                                        activeRequestIds = emptyMap()
                                        status = "Berhasil keluar."
                                    },
                                    enabled = !working,
                                )
                            }
                        }
                        Spacer(Modifier.height(18.dp))
                        SwaraCard {
                            Text("Penyimpanan rekaman", fontSize = 18.sp, color = Plum)
                            Text(
                                if (policy == null) "Tersimpan terenkripsi di perangkat ini."
                                else "Salinan terenkripsi dengan perangkat terpercaya.",
                                color = Muted,
                            )
                            if (policy != null) Pill("Gunakan penyimpanan lokal", { policy = null })
                        }
                    }
                }
                Spacer(Modifier.height(24.dp))
            }
        }
    auditText?.let { text ->
        AlertDialog(
            onDismissRequest = {
                auditText = null
                pendingLink = null
            },
            title = { Text(if (pendingLink == null) "Audit rekaman" else "Cocokkan fingerprint") },
            text = {
                SelectionContainer {
                    Text(text, Modifier.verticalScroll(rememberScrollState()), fontSize = 13.sp)
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        pendingLink?.let { link ->
                            action {
                                client!!.confirm(link, core.identity)
                                refresh()
                                status = "Konfirmasi tersimpan."
                            }
                        }
                        auditText = null
                        pendingLink = null
                    }
                ) {
                    Text(if (pendingLink == null) "Tutup" else "Sudah cocok")
                }
            },
            dismissButton =
                if (pendingLink != null) {
                    {
                        TextButton(
                            onClick = {
                                auditText = null
                                pendingLink = null
                            }
                        ) {
                            Text("Batal")
                        }
                    }
                } else null,
        )
    }
}

@Composable
private fun EmptyState(title: String, detail: String, icon: String) {
    Column(
        Modifier.fillMaxWidth().padding(vertical = 34.dp, horizontal = 20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        SwaraIcon(icon, Modifier.size(30.dp), Muted)
        Text(title, color = Plum, fontSize = 16.sp)
        Text(
            detail,
            color = Muted,
            fontSize = 13.sp,
            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
        )
    }
}
