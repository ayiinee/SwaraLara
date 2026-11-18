package id.swaralara.core

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import kotlinx.coroutines.*

@Composable
fun RecorderPanel(controller: RecorderController, modifier: Modifier = Modifier, holdMillis: Long = 1500,
    captureConfig: CaptureConfig = CaptureConfig()) {
    require(holdMillis > 0)
    val state by controller.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var permission by remember { mutableStateOf(ContextCompat.checkSelfPermission(context,Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) }
    var notifications by remember { mutableStateOf(Build.VERSION.SDK_INT < 33 ||
        ContextCompat.checkSelfPermission(context,Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        permission = ContextCompat.checkSelfPermission(context,Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        notifications = Build.VERSION.SDK_INT < 33 ||
            ContextCompat.checkSelfPermission(context,Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }
    var message by remember { mutableStateOf<String?>(null) }
    var holding by remember { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        permission = it; message = if (it) "Izin diberikan. Tahan tombol untuk mulai." else "Izin mikrofon ditolak. Aktifkan izin untuk merekam."
    }
    val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { notifications = it }
    Column(modifier.padding(16.dp),verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(if(captureConfig.cloudPolicy==null) "Perlindungan lokal — belum memiliki pemulihan bersama"
            else "Salinan cloud terenkripsi — pemulihan bersama belum aktif",style = MaterialTheme.typography.titleMedium)
        Text("Gunakan ucapan simulasi. Rekaman dimulai setelah mikrofon aktif.")
        if (!permission) Button(onClick = { launcher.launch(Manifest.permission.RECORD_AUDIO) }) { Text("Izinkan mikrofon") }
        if (!notifications && Build.VERSION.SDK_INT >= 33) {
            OutlinedButton(onClick = { notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }) { Text("Izinkan notifikasi perekaman") }
            Text("Notifikasi menyediakan aksi Hentikan. Jika izin ditolak, Android tetap mengatur indikator layanan dan mikrofon.")
        }
        Surface(color = if (holding) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.primaryContainer,
            shape = MaterialTheme.shapes.large,
            modifier = Modifier.fillMaxWidth().heightIn(min = 88.dp)
                .semantics { contentDescription = "Tahan untuk merekam" }
                .pointerInput(controller, state.busy, permission, holdMillis,captureConfig) {
                    detectTapGestures(onPress = {
                        if (state.busy || !permission) return@detectTapGestures
                        coroutineScope {
                            holding = true
                            val activation = launch {
                                delay(holdMillis)
                                holding = false
                                scope.launch {
                                    try { controller.start(captureConfig); message = null }
                                    catch (_: Exception) { message = "Perekaman tidak dapat dimulai. Periksa izin dan status mikrofon." }
                                }
                            }
                            try { tryAwaitRelease() } finally { activation.cancel(); holding = false }
                        }
                    })
                }) {
            Column(Modifier.padding(20.dp)) {
                Text(if (holding) "Terus tahan…" else "Tahan untuk merekam",style = MaterialTheme.typography.titleLarge)
                Text("Ambang ${holdMillis / 1000.0} detik • Lepas setelah aktif tetap merekam")
            }
        }
        Text("Status: ${captureLabel(state.capture)}")
        Text("${"%.2f".format(state.frames.toDouble() / state.sampleRate)} dtk aman • ${state.savedSegments} segmen • ${state.encryptedBytes} byte terenkripsi")
        state.errorCode?.let { Text("Gagal: $it. Periksa izin, mikrofon, dan ruang penyimpanan.",color = MaterialTheme.colorScheme.error) }
        message?.let { Text(it) }
        Button(enabled = state.busy,onClick = {
            scope.launch { try { controller.stop() } catch (_: Exception) { message = "Belum dapat menghentikan layanan. Gunakan aksi Hentikan pada notifikasi." } }
        }) { Text("Hentikan") }
    }
}

private fun captureLabel(state: CaptureState) = when(state) {
    CaptureState.IDLE -> "Siap"; CaptureState.STARTING -> "Menyiapkan mikrofon"
    CaptureState.RECORDING -> "Merekam"; CaptureState.STOPPING -> "Menyimpan sisa audio"
    CaptureState.SEALED -> "Tersimpan lokal"; CaptureState.INTERRUPTED -> "Terputus — mungkin parsial"
    CaptureState.FAILED -> "Gagal"
}

@Composable
fun SecurePlaybackPanel(controller: SecurePlaybackController, modifier: Modifier = Modifier) {
    val state by controller.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    Column(modifier.padding(8.dp),verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Player: ${state.phase} • ${state.positionFrames}/${state.totalFrames} frame")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = state.phase in setOf(PlaybackPhase.PREPARED,PlaybackPhase.PAUSED,PlaybackPhase.COMPLETED),
                onClick = { scope.launch { controller.play() } }) { Text("Putar") }
            OutlinedButton(enabled = state.phase == PlaybackPhase.PLAYING,onClick = { scope.launch { controller.pause() } }) { Text("Jeda") }
            OutlinedButton(onClick = { scope.launch { controller.release() } }) { Text("Tutup") }
        }
        state.errorCode?.let { Text("Pemutaran gagal: $it",color = MaterialTheme.colorScheme.error) }
    }
}
