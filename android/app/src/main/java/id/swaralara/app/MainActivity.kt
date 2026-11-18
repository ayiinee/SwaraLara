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

class MainActivity: ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val core=CoreRuntime.get(applicationContext)
        setContent {MaterialTheme {Surface(Modifier.fillMaxSize()) {ConnectedScreen(core,this)}}}
    }
    override fun onStop(){CoreRuntime.get(applicationContext).onHostBackgrounded();super.onStop()}
}

@Composable private fun ConnectedScreen(core: CoreRuntime,context: android.content.Context) {
    val scope=rememberCoroutineScope()
    val url=BuildConfig.SUPABASE_URL.trimEnd('/')
    val sessions=remember {SessionStore(context,url)}
    val client=remember {if(url.isBlank()||BuildConfig.SUPABASE_PUBLISHABLE_KEY.isBlank())null else
        runCatching {CloudClient(url,BuildConfig.SUPABASE_PUBLISHABLE_KEY,sessions)}.getOrNull()}
    var session by remember {mutableStateOf(sessions.load())}
    var email by remember {mutableStateOf("")};var password by remember {mutableStateOf("")}
    var token by remember {mutableStateOf("")};var invitation by remember {mutableStateOf("")}
    var links by remember {mutableStateOf<List<JSONObject>>(emptyList())}
    var policy by remember {mutableStateOf<CloudCapturePolicy?>(null)}
    var status by remember {mutableStateOf("Rekam lokal tetap tersedia tanpa login.")}
    var working by remember {mutableStateOf(false)}
    val recordingFlow=remember(core) {core.vault.observeRecordings().catch {status="Brankas belum dapat dibaca. Data lokal dipertahankan.";emit(emptyList())}}
    val recordings by recordingFlow.collectAsStateWithLifecycle(emptyList())
    val capture by core.recorder.state.collectAsStateWithLifecycle()
    fun action(block: suspend ()->Unit) {
        if(working)return;working=true
        scope.launch {try{core.awaitReady();block()}catch(e:CancellationException){throw e}
            catch(e:CloudError){status="Backend: ${e.code} (${e.status}). Data lokal dipertahankan."}
            catch(_:Exception){status="Operasi belum berhasil. Periksa konfigurasi, koneksi, identitas perangkat, dan izin."}
            finally{working=false}}
    }
    suspend fun refresh() {val a=client!!.links();links=(0 until a.length()).map {a.getJSONObject(it)}}
    LaunchedEffect(recordings,session?.userId) {
        if(client!=null && session!=null) {
            recordings.filter {it.capture in setOf(CaptureState.SEALED,CaptureState.INTERRUPTED) && it.recovery==RecoveryState.DEGRADED && it.sync==SyncState.QUEUED}
                .forEach {UploadWorker.enqueue(context,it.id)}
        }
    }
    Column(Modifier.systemBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
        Text("SwaraLara",style=MaterialTheme.typography.headlineMedium)
        Text("M2 • Salinan ciphertext. Pemulihan lintas perangkat belum aktif.")
        if(client==null) Text("Backend belum dikonfigurasi. Isi SUPABASE_URL dan SUPABASE_PUBLISHABLE_KEY di local.properties lalu build app.")
        else if(session==null) {
            OutlinedTextField(email,{email=it},label={Text("Email akun uji")},singleLine=true)
            OutlinedTextField(password,{password=it},label={Text("Kata sandi")},visualTransformation=PasswordVisualTransformation(),singleLine=true)
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                Button(enabled=!working,onClick={action{session=client.login(email,password);password="";client.register(core.identity.publicIdentity());refresh();status="Login dan perangkat terdaftar."}}){Text("Login")}
                OutlinedButton(enabled=!working,onClick={action{session=client.signup(email,password);password="";status=if(session==null)"Konfirmasi email melalui email/Inbox lokal lalu login." else "Akun dibuat; login untuk mendaftarkan perangkat."}}){Text("Daftar")}
            }
        } else {
            Text("Akun: ${session!!.userId}")
            OutlinedButton(enabled=!working,onClick={action{client.register(core.identity.publicIdentity());refresh();status="Perangkat dan hubungan dimuat."}}){Text("Daftarkan perangkat / muat hubungan")}
            Button(enabled=!working,onClick={action{val result=client.api("/trust/invitations","POST",JSONObject().put("deviceId",core.identity.publicIdentity().deviceId)) as JSONObject
                invitation=result.getString("token");status="Undangan satu kali, berlaku 15 menit. Bagikan hanya kepada pihak yang dipilih."}}){Text("Buat undangan")}
            if(invitation.isNotEmpty())Text(invitation)
            OutlinedTextField(token,{token=it},label={Text("Token undangan dari pemilik")})
            OutlinedButton(enabled=!working,onClick={action{client.api("/trust/accept","POST",JSONObject().put("token",token).put("deviceId",core.identity.publicIdentity().deviceId));token="";refresh();status="Bandingkan fingerprint melalui saluran terpisah sebelum konfirmasi."}}){Text("Terima undangan")}
            links.forEach {link->
                val owner=link.getJSONObject("ownerDevice");val holder=link.getJSONObject("holderDevice")
                Text("Hubungan ${link.getString("id")} • ${link.getString("state")}")
                Text("Fingerprint pemilik (signing/HPKE):\n${owner.getString("signing_fingerprint")}\n${owner.getString("hpke_fingerprint")}")
                Text("Fingerprint pemegang (signing/HPKE):\n${holder.getString("signing_fingerprint")}\n${holder.getString("hpke_fingerprint")}")
                OutlinedButton(enabled=!working,onClick={action{client.confirm(link,core.identity);refresh();status="Konfirmasi tersimpan. Kedua pihak wajib mengonfirmasi fingerprint."}}){Text("Fingerprint sudah saya cocokkan")}
                if(link.getString("owner_user_id")==session!!.userId.toString() && link.getString("state")=="active") {
                    Button(enabled=!working&&sessions.pinned(link),onClick={action{
                        check(sessions.pinned(link));val own=core.identity.publicIdentity()
                        policy=CloudCapturePolicy(session!!.userId,own.deviceId,"owner_required_2of2",listOf(
                            CloudMember(1,session!!.userId,own.deviceId,own.hpkeFingerprint,own.signingFingerprint),
                            CloudMember(2,UUID.fromString(link.getString("holder_user_id")),UUID.fromString(holder.getString("id")),holder.getString("hpke_fingerprint"),holder.getString("signing_fingerprint"))))
                        status="Rekaman baru memakai snapshot pemilik + satu pemegang. M3 memerlukan keduanya untuk pemulihan; kehilangan salah satu bagian dapat menghalangi akses. Pada M2 envelope DEK lokal tetap disimpan; bagian belum didistribusikan."
                    }}){Text("Pilih kebijakan pemilik + pemegang")}
                }
            }
            OutlinedButton(enabled=!working,onClick={action{val requests=client.accessRequests();status="Inbox akses: ${requests.length()} permintaan."}}){Text("Muat inbox permintaan akses")}
            OutlinedButton(onClick={policy=null;sessions.clear();session=null;links=emptyList();invitation="";status="Keluar. Rekaman dan kunci lokal dipertahankan."}){Text("Keluar")}
        }
        Text(status)
        if(policy!=null)OutlinedButton(onClick={policy=null}){Text("Kembali ke rekaman lokal")}
        RecorderPanel(core.recorder,captureConfig=CaptureConfig(cloudPolicy=policy))
        Text("Brankas lokal",style=MaterialTheme.typography.titleLarge)
        recordings.forEach {r->
            Text("${r.id} • ${r.capture} • ${r.sync} • Pemulihan ${r.recovery}")
            if(r.recovery==RecoveryState.DEGRADED && r.capture in setOf(CaptureState.SEALED,CaptureState.INTERRUPTED)) {
                Button(enabled=!working&&session!=null,onClick={UploadWorker.enqueue(context,r.id);status="Antrean unggah dijadwalkan. Ciphertext dan DEK lokal dipertahankan."}){Text("Unggah / coba lagi")}
            } else Text("Rekaman demo tetap lokal.")
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                OutlinedButton(enabled=!capture.busy,onClick={action{status=core.vault.inspect(r.id).message}}){Text("Periksa")}
                OutlinedButton(enabled=!capture.busy,onClick={action{core.playback.prepare(r.id)}}){Text("Siapkan player")}
            }
        }
        SecurePlaybackPanel(core.playback)
    }
}
