package id.swaralara.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import id.swaralara.app.backend.*
import id.swaralara.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.catch
import org.json.JSONObject
import java.util.UUID

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val core = CoreRuntime.get(applicationContext)
        setContent { MaterialTheme { Surface(Modifier.fillMaxSize()) { ConnectedScreen(core, this) } } }
    }
    override fun onStop() { CoreRuntime.get(applicationContext).onHostBackgrounded(); super.onStop() }
}

@Composable private fun ConnectedScreen(core: CoreRuntime, context: android.content.Context) {
    val scope = rememberCoroutineScope()
    val url = BuildConfig.SUPABASE_URL.trimEnd('/')
    val sessions = remember { SessionStore(context, url) }
    val client = remember {
        if (url.isBlank() || BuildConfig.SUPABASE_PUBLISHABLE_KEY.isBlank()) null
        else runCatching { CloudClient(url, BuildConfig.SUPABASE_PUBLISHABLE_KEY, sessions) }.getOrNull()
    }
    var session by remember { mutableStateOf(sessions.load()) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf("") }
    var links by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var policy by remember { mutableStateOf<CloudCapturePolicy?>(null) }
    var status by remember { mutableStateOf("Rekam lokal tetap tersedia tanpa login.") }
    var working by remember { mutableStateOf(false) }

    // M3: inbox persetujuan pemegang
    var accessRequests by remember { mutableStateOf<List<KeyAccessRequest>>(emptyList()) }
    // M3: requestId aktif per recordingId (untuk pemulihan DEK)
    var activeRequestIds by remember { mutableStateOf<Map<UUID, UUID>>(emptyMap()) }

    val recordingFlow = remember(core) {
        core.vault.observeRecordings()
            .catch { status = "Brankas belum dapat dibaca. Data lokal dipertahankan."; emit(emptyList()) }
    }
    val recordings by recordingFlow.collectAsStateWithLifecycle(emptyList())
    val capture by core.recorder.state.collectAsStateWithLifecycle()

    fun action(block: suspend () -> Unit) {
        if (working) return; working = true
        scope.launch {
            try {
                core.awaitReady(); block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: CloudError) {
                status = "Backend: ${e.code} (${e.status}). Data lokal dipertahankan."
            } catch (_: Exception) {
                status = "Operasi belum berhasil. Periksa konfigurasi, koneksi, identitas perangkat, dan izin."
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
            recordings.filter {
                it.capture in setOf(CaptureState.SEALED, CaptureState.INTERRUPTED)
                    && it.recovery == RecoveryState.DEGRADED
                    && it.sync == SyncState.QUEUED
            }.forEach { UploadWorker.enqueue(context, it.id) }

            // M3: enqueue EnvelopeWorker untuk rekaman yang sudah SYNCED & siap distribusi
            recordings.filter {
                it.sync == SyncState.SYNCED
                    && it.recovery == RecoveryState.ENVELOPES_QUEUED
            }.forEach { EnvelopeWorker.enqueue(context, it.id) }

            // M3: poll RecoveryWorker sekali saat login (KEEP — tidak duplikat)
            RecoveryWorker.enqueueOnce(context)
        }
    }

    Column(
        Modifier
            .systemBarsPadding()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("SwaraLara", style = MaterialTheme.typography.headlineMedium)
        // M3: label versi
        Text("M3 • Distribusi kunci threshold & pemulihan lintas perangkat aktif.")

        if (client == null) {
            Text("Backend belum dikonfigurasi. Isi SUPABASE_URL dan SUPABASE_PUBLISHABLE_KEY di local.properties lalu build app.")
        } else if (session == null) {
            OutlinedTextField(email, { email = it }, label = { Text("Email akun uji") }, singleLine = true)
            OutlinedTextField(
                password, { password = it },
                label = { Text("Kata sandi") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(enabled = !working, onClick = {
                    action {
                        session = client.login(email, password); password = ""
                        client.register(core.identity.publicIdentity()); refresh()
                        status = "Login dan perangkat terdaftar."
                    }
                }) { Text("Login") }
                OutlinedButton(enabled = !working, onClick = {
                    action {
                        session = client.signup(email, password); password = ""
                        status = if (session == null)
                            "Konfirmasi email melalui email/Inbox lokal lalu login."
                        else
                            "Akun dibuat; login untuk mendaftarkan perangkat."
                    }
                }) { Text("Daftar") }
            }
        } else {
            // ── Informasi akun ──────────────────────────────────────────────
            Text("Akun: ${session!!.userId}")
            OutlinedButton(enabled = !working, onClick = {
                action { client.register(core.identity.publicIdentity()); refresh(); status = "Perangkat dan hubungan dimuat." }
            }) { Text("Daftarkan perangkat / muat hubungan") }

            Button(enabled = !working, onClick = {
                action {
                    val result = client.api("/trust/invitations", "POST",
                        JSONObject().put("deviceId", core.identity.publicIdentity().deviceId)) as JSONObject
                    invitation = result.getString("token")
                    status = "Undangan satu kali, berlaku 15 menit. Bagikan hanya kepada pihak yang dipilih."
                }
            }) { Text("Buat undangan") }
            if (invitation.isNotEmpty()) Text(invitation)

            OutlinedTextField(token, { token = it }, label = { Text("Token undangan dari pemilik") })
            OutlinedButton(enabled = !working, onClick = {
                action {
                    client.api("/trust/accept", "POST",
                        JSONObject().put("token", token).put("deviceId", core.identity.publicIdentity().deviceId))
                    token = ""; refresh()
                    status = "Bandingkan fingerprint melalui saluran terpisah sebelum konfirmasi."
                }
            }) { Text("Terima undangan") }

            links.forEach { link ->
                val owner = link.getJSONObject("ownerDevice")
                val holder = link.getJSONObject("holderDevice")
                Text("Hubungan ${link.getString("id")} • ${link.getString("state")}")
                Text("Fingerprint pemilik (signing/HPKE):\n${owner.getString("signing_fingerprint")}\n${owner.getString("hpke_fingerprint")}")
                Text("Fingerprint pemegang (signing/HPKE):\n${holder.getString("signing_fingerprint")}\n${holder.getString("hpke_fingerprint")}")
                OutlinedButton(enabled = !working, onClick = {
                    action { client.confirm(link, core.identity); refresh(); status = "Konfirmasi tersimpan. Kedua pihak wajib mengonfirmasi fingerprint." }
                }) { Text("Fingerprint sudah saya cocokkan") }
                if (link.getString("owner_user_id") == session!!.userId.toString() && link.getString("state") == "active") {
                    Button(enabled = !working && sessions.pinned(link), onClick = {
                        action {
                            check(sessions.pinned(link))
                            val own = core.identity.publicIdentity()
                            policy = CloudCapturePolicy(
                                session!!.userId, own.deviceId, "owner_required_2of2",
                                listOf(
                                    CloudMember(1, session!!.userId, own.deviceId, own.hpkeFingerprint, own.signingFingerprint),
                                    CloudMember(2, UUID.fromString(link.getString("holder_user_id")),
                                        UUID.fromString(holder.getString("id")),
                                        holder.getString("hpke_fingerprint"),
                                        holder.getString("signing_fingerprint"))
                                )
                            )
                            status = "Rekaman baru memakai snapshot pemilik + satu pemegang. M3 mendistribusikan envelope DEK terenkripsi ke pemegang; pemulihan memerlukan persetujuan threshold."
                        }
                    }) { Text("Pilih kebijakan pemilik + pemegang") }
                }
            }

            OutlinedButton(onClick = {
                policy = null; sessions.clear(); session = null
                links = emptyList(); invitation = ""; accessRequests = emptyList()
                activeRequestIds = emptyMap()
                status = "Keluar. Rekaman dan kunci lokal dipertahankan."
            }) { Text("Keluar") }

            // ── M3: Pemulihan M3 ────────────────────────────────────────────
            Text("Pemulihan M3", style = MaterialTheme.typography.titleMedium)

            // Distribusi kunci — per rekaman yang siap distribusi
            val envelopeReady = recordings.filter {
                it.recovery == RecoveryState.ENVELOPES_QUEUED || it.recovery == RecoveryState.ENVELOPES_UPLOADED
            }
            if (envelopeReady.isNotEmpty()) {
                Text("Distribusi envelope DEK:", style = MaterialTheme.typography.labelLarge)
                envelopeReady.forEach { r ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("${r.id.toString().take(8)}… • ${recoveryLabel(r.recovery)}", Modifier.weight(1f))
                        Button(enabled = !working, onClick = {
                            action { EnvelopeWorker.enqueue(context, r.id); status = "Distribusi kunci dijadwalkan untuk rekaman ${r.id}." }
                        }) { Text("Distribusi kunci") }
                    }
                }
            }

            // Inbox persetujuan pemegang
            Button(enabled = !working, onClick = {
                action {
                    accessRequests = client.getAccessRequests()
                    status = "Inbox dimuat: ${accessRequests.size} permintaan."
                }
            }) { Text("Muat inbox persetujuan") }

            if (accessRequests.isNotEmpty()) {
                Text("Permintaan akses (${accessRequests.size}):", style = MaterialTheme.typography.labelLarge)
                accessRequests.forEach { req ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Permintaan ${req.requestId.toString().take(8)}… — rekaman ${req.recordingId.toString().take(8)}…")
                        Button(enabled = !working, onClick = {
                            action {
                                val release = core.keyExchange.approveAndRelease(req, userApproved = true)
                                client.approveRelease(req.requestId, release)
                                status = "Persetujuan dikirim untuk permintaan ${req.requestId.toString().take(8)}…"
                            }
                        }) { Text("Setujui & Lepaskan") }
                    }
                }
            }

            // Minta pemulihan — per rekaman HOLDERS_ACKNOWLEDGED
            val holdersReady = recordings.filter { it.recovery == RecoveryState.HOLDERS_ACKNOWLEDGED }
            if (holdersReady.isNotEmpty()) {
                Text("Siap minta pemulihan:", style = MaterialTheme.typography.labelLarge)
                holdersReady.forEach { r ->
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Rekaman ${r.id.toString().take(8)}… — Pemegang siap — dapat meminta pemulihan")
                        val existingReqId = activeRequestIds[r.id]
                        if (existingReqId == null) {
                            Button(enabled = !working, onClick = {
                                action {
                                    val policyPkg = core.keyExchange.exportPolicy(r.id)
                                    val request = core.keyExchange.createRequest(policyPkg)
                                    val createdReqId = client.createAccessRequest(request)
                                    activeRequestIds = activeRequestIds + (r.id to createdReqId)
                                    status = "Permintaan pemulihan dibuat: $createdReqId"
                                }
                            }) { Text("Minta pemulihan") }
                        } else {
                            Text("RequestId aktif: ${existingReqId.toString().take(8)}…")
                            Button(enabled = !working, onClick = {
                                action {
                                    val auth = core.keyExchange.authorizeReleasesRead(existingReqId)
                                    val releases = client.getReleases(existingReqId, auth)
                                    core.keyExchange.recover(existingReqId, releases)
                                    status = "DEK berhasil dipulihkan untuk rekaman ${r.id.toString().take(8)}…"
                                }
                            }) { Text("Ambil releases & pulihkan") }
                        }
                    }
                }
            }
        }

        Text(status)
        if (policy != null) OutlinedButton(onClick = { policy = null }) { Text("Kembali ke rekaman lokal") }
        RecorderPanel(core.recorder, captureConfig = CaptureConfig(cloudPolicy = policy))

        // ── Brankas lokal ───────────────────────────────────────────────────
        Text("Brankas lokal", style = MaterialTheme.typography.titleLarge)
        recordings.forEach { r ->
            Text("${r.id} • ${r.capture} • ${r.sync} • Pemulihan ${r.recovery}")
            if (r.recovery == RecoveryState.DEGRADED && r.capture in setOf(CaptureState.SEALED, CaptureState.INTERRUPTED)) {
                Button(
                    enabled = !working && session != null,
                    onClick = { UploadWorker.enqueue(context, r.id); status = "Antrean unggah dijadwalkan. Ciphertext dan DEK lokal dipertahankan." }
                ) { Text("Unggah / coba lagi") }
            } else {
                // M3: tampilkan status recovery yang informatif
                when (r.recovery) {
                    RecoveryState.ENVELOPES_QUEUED -> Text("Kunci siap didistribusikan")
                    RecoveryState.ENVELOPES_UPLOADED -> Text("Menunggu konfirmasi pemegang")
                    RecoveryState.HOLDERS_ACKNOWLEDGED -> Text("Pemegang siap — dapat meminta pemulihan")
                    else -> Text("Rekaman demo tetap lokal.")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled = !capture.busy, onClick = { action { status = core.vault.inspect(r.id).message } }) { Text("Periksa") }
                OutlinedButton(enabled = !capture.busy, onClick = { action { core.playback.prepare(r.id) } }) { Text("Siapkan player") }
            }
        }
        SecurePlaybackPanel(core.playback)
    }
}

private fun recoveryLabel(state: RecoveryState): String = when (state) {
    RecoveryState.ENVELOPES_QUEUED -> "Kunci siap didistribusikan"
    RecoveryState.ENVELOPES_UPLOADED -> "Menunggu konfirmasi pemegang"
    RecoveryState.HOLDERS_ACKNOWLEDGED -> "Pemegang siap — dapat meminta pemulihan"
    else -> state.name
}
