package id.swaralara.coredemo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import id.swaralara.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.catch
import java.text.DateFormat
import java.util.Date
import java.util.UUID

class MainActivity : ComponentActivity() {
    override fun onStop() {
        CoreRuntime.get(applicationContext).onHostBackgrounded()
        super.onStop()
    }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val core = CoreRuntime.get(applicationContext)
        setContent {
            MaterialTheme(colorScheme = lightColorScheme(primary = Color(0xFF6B3F69), background = Color(0xFFFAF7FA))) {
                Surface(Modifier.fillMaxSize()) { DemoScreen(core) }
            }
        }
    }
}

@Composable private fun DemoScreen(core: CoreRuntime) {
    var vaultReadFailed by remember { mutableStateOf(false) }
    val recordingFlow = remember(core) {
        core.vault.observeRecordings().catch { error ->
            if (error is CancellationException) throw error
            vaultReadFailed = true
            emit(emptyList())
        }
    }
    val recordings by recordingFlow.collectAsStateWithLifecycle(emptyList())
    val recorder by core.recorder.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf<UUID?>(null) }
    var diagnostic by remember { mutableStateOf("Pilih rekaman untuk memeriksa dan memutar.") }
    var working by remember { mutableStateOf(false) }
    fun action(block: suspend () -> String) {
        if (working) return
        working = true
        scope.launch {
            try { diagnostic = block() }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { diagnostic = "Operasi gagal. Kunci lokal atau paket belum dapat diverifikasi; rekaman asli dipertahankan." }
            finally { working = false }
        }
    }
    Column(Modifier.fillMaxSize().systemBarsPadding().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("SwaraLara • Core Demo",style = MaterialTheme.typography.headlineMedium)
        Text("Demo lokal — data simulasi",style = MaterialTheme.typography.titleMedium)
        Text("Pembagian kunci pada satu perangkat • Demo algoritma lokal")
        RecorderPanel(core.recorder)
        HorizontalDivider()
        Text("Brankas lokal (${recordings.size})",style = MaterialTheme.typography.titleLarge)
        if (vaultReadFailed) Text("Brankas belum dapat dibaca. Periksa ruang penyimpanan lalu mulai ulang aplikasi.",color = MaterialTheme.colorScheme.error)
        else if (recordings.isEmpty()) Text("Belum ada rekaman. Izinkan mikrofon, lalu tahan tombol.")
        recordings.forEach { recording ->
            OutlinedButton(modifier = Modifier.fillMaxWidth(),enabled = !recorder.busy && !working,
                onClick = { selected = recording.id; diagnostic = "Rekaman dipilih; belum diverifikasi."; scope.launch { core.playback.release() } }) {
                Column(Modifier.fillMaxWidth()) {
                    Text(if (recording.kind == "live_event") "Rekaman kejadian (waktu perangkat)" else "Penuturan simulasi")
                    Text(DateFormat.getDateTimeInstance().format(Date(recording.startedAtDevice)))
                    Text("${"%.2f".format(recording.frames.toDouble()/recording.sampleRate)} dtk • ${recording.segmentCount} segmen • ${recording.capture}")
                    Text("Sync ${recording.sync} • Recovery ${recording.recovery} • Integritas ${recording.integrity}")
                    if (selected == recording.id) Text("Dipilih")
                }
            }
        }
        selected?.let { id ->
            Text("Pemeriksaan rekaman",style = MaterialTheme.typography.titleLarge)
            Button(enabled = !working && !recorder.busy,onClick = { action { core.vault.inspect(id).message } }) { Text("Periksa keutuhan") }
            Button(enabled = !working && !recorder.busy,onClick = { action { core.vault.demonstrateRecovery(id).message } }) { Text("Uji pemulihan 2 dari 3") }
            OutlinedButton(enabled = !working && !recorder.busy,onClick = { action {
                if (core.vault.testCorruptionOnCopy(id)) "Lulus: korupsi salinan di memori ditolak GCM. Rekaman asli tidak diubah."
                else "Gagal: korupsi tidak ditolak."
            } }) { Text("Uji korupsi pada salinan") }
            Button(enabled = !working && !recorder.busy,onClick = { action {
                if (core.playback.prepare(id)) "Segmen diperiksa. Player siap." else "Player gagal: kunci atau segmen tidak dapat diverifikasi."
            } }) { Text("Siapkan pemutaran") }
            SecurePlaybackPanel(core.playback)
        }
        Text(diagnostic)
        Text("M2–M4 belum aktif: backend, perangkat pemegang, HPKE, manifest/signature, dan persetujuan akses.")
        Text("Pemeriksaan keutuhan tidak membuktikan kebenaran isi atau waktu kejadian. Demo belum untuk pengaduan nyata.")
    }
}
