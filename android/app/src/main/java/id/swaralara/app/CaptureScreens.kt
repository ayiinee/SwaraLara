package id.swaralara.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import id.swaralara.core.*
import kotlinx.coroutines.*

@Composable
internal fun CaptureCard(core: CoreRuntime, policy: CloudCapturePolicy?, report: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var live by rememberSaveable { mutableStateOf(true) }
    var holding by remember { mutableStateOf(false) }
    var allowed by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED
        )
    }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
            allowed = it
            report(
                if (it) "Mikrofon siap. Tahan tombol selama 1,5 detik untuk merekam."
                else "Izinkan mikrofon di pengaturan perangkat untuk merekam."
            )
        }
    val notifications =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        allowed =
            ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) ==
                PackageManager.PERMISSION_GRANTED
    }
    SwaraCard {
        Text("Rekam sekarang", fontSize = 18.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(true to "Kejadian", false to "Penuturan").forEach { (value, label) ->
                OutlinedButton(
                    onClick = { live = value },
                    modifier = Modifier.weight(1f).height(39.dp),
                    shape = RoundedCornerShape(8.dp),
                    contentPadding = PaddingValues(6.dp),
                    colors =
                        ButtonDefaults.outlinedButtonColors(
                            containerColor = if (live == value) Pink else Color.Transparent,
                            contentColor = if (live == value) Color.White else Ink,
                        ),
                    border =
                        androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (live == value) Pink else Plum,
                        ),
                ) {
                    SwaraIcon(
                        if (value) "mic" else "document",
                        Modifier.size(21.dp),
                        if (live == value) Color.White else Plum,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(label, fontSize = 12.sp)
                }
            }
        }
        Row(
            Modifier.fillMaxWidth()
                .background(SoftPink.copy(alpha = .6f), RoundedCornerShape(12.dp))
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            SwaraIcon(if (live) "mic" else "document", Modifier.size(23.dp), Pink)
            Column {
                Text(
                    if (live) "Sedang terjadi" else "Ceritakan kembali",
                    color = Pink,
                    fontSize = 13.sp,
                )
                Text(
                    if (live) "Rekam saat kejadian berlangsung."
                    else "Rekam penuturan setelah kejadian.",
                    fontSize = 11.sp,
                    color = Muted,
                )
            }
        }
        Surface(
            color = Plum,
            shape = RoundedCornerShape(23.dp),
            modifier =
                Modifier.fillMaxWidth()
                    .height(108.dp)
                    .semantics { contentDescription = "Tahan untuk merekam" }
                    .pointerInput(live, allowed, policy) {
                        detectTapGestures(
                            onPress = {
                                if (!allowed) {
                                    launcher.launch(Manifest.permission.RECORD_AUDIO)
                                    return@detectTapGestures
                                }
                                coroutineScope {
                                    holding = true
                                    val activation = launch {
                                        delay(1500)
                                        holding = false
                                        scope.launch {
                                            try {
                                                core.awaitReady()
                                                core.recorder.start(
                                                    CaptureConfig(
                                                        kind =
                                                            if (live) "live_event"
                                                            else "retrospective",
                                                        cloudPolicy = policy,
                                                    )
                                                )
                                                if (
                                                    Build.VERSION.SDK_INT >= 33 &&
                                                        ContextCompat.checkSelfPermission(
                                                            context,
                                                            Manifest.permission.POST_NOTIFICATIONS,
                                                        ) != PackageManager.PERMISSION_GRANTED
                                                )
                                                    notifications.launch(
                                                        Manifest.permission.POST_NOTIFICATIONS
                                                    )
                                            } catch (e: CancellationException) {
                                                throw e
                                            } catch (_: Exception) {
                                                report(
                                                    "Perekaman belum dapat dimulai. Periksa izin mikrofon dan ruang penyimpanan."
                                                )
                                            }
                                        }
                                    }
                                    try {
                                        tryAwaitRelease()
                                    } finally {
                                        activation.cancel()
                                        holding = false
                                    }
                                }
                            }
                        )
                    },
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(
                    if (holding) "Terus tahan…" else "Tahan untuk merekam",
                    color = Color.White,
                    fontSize = 17.sp,
                )
            }
        }
        Button(
            onClick = {},
            enabled = false,
            modifier = Modifier.fillMaxWidth().height(40.dp),
            colors =
                ButtonDefaults.buttonColors(
                    disabledContainerColor = Hairline,
                    disabledContentColor = Muted,
                ),
        ) {
            Text("Berhenti merekam", fontSize = 12.sp)
        }
    }
}

@Composable
internal fun RecordingScreen(state: RecorderState, stop: () -> Unit) {
    BoxWithConstraints(Modifier.fillMaxSize().systemBarsPadding().padding(horizontal = 20.dp)) {
        Column(
            Modifier.fillMaxWidth().padding(top = maxHeight * .25f),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(17.dp),
        ) {
            Box(
                Modifier.size(108.dp).background(Plum, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                SwaraIcon("mic", Modifier.size(44.dp), Color.White)
            }
            Text("Sedang terjadi", color = Pink, fontSize = 18.sp)
            Text(
                when (state.capture) {
                    CaptureState.STARTING -> "Menyiapkan"
                    CaptureState.STOPPING -> "Menyimpan"
                    else -> "Merekam"
                },
                color = Plum,
                fontSize = 28.sp,
                fontWeight = FontWeight.Medium,
            )
            Text(
                duration(state.frames, state.sampleRate),
                color = Plum,
                fontSize = 48.sp,
                fontWeight = FontWeight.Medium,
            )
            Text("${state.savedSegments} segmen", color = Muted, fontSize = 18.sp)
        }
        Button(
            onClick = stop,
            enabled = state.capture != CaptureState.STOPPING,
            modifier =
                Modifier.align(Alignment.BottomCenter)
                    .fillMaxWidth()
                    .padding(bottom = 28.dp)
                    .height(52.dp),
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC9191D)),
        ) {
            Text("Berhenti merekam", fontSize = 16.sp)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun RecordingDetail(
    r: RecordingSummary,
    playback: PlaybackState,
    working: Boolean,
    inspect: () -> Unit,
    prepare: () -> Unit,
    audit: () -> Unit,
    play: () -> Unit,
    pause: () -> Unit,
    close: () -> Unit,
) {
    SwaraCard {
        Text(recordingName(r), fontSize = 23.sp, color = Plum)
        Text(
            "${recordingDate(r.startedAtDevice)} · ${duration(r.frames,r.sampleRate)}",
            fontSize = 15.sp,
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Badge(captureBadge(r))
            Badge(r.integrity.name.replace('_', ' '))
            Badge(r.sync.name.replace('_', ' '))
        }
        HorizontalDivider(color = Hairline)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Pill("Periksa", inspect, Modifier.weight(1f), enabled = !working)
            Pill("Putar", prepare, Modifier.weight(1f), enabled = !working)
            Pill("Audit", audit, Modifier.weight(1f), enabled = !working)
        }
    }
    Spacer(Modifier.height(17.dp))
    Text(
        "${playback.positionFrames}/${playback.totalFrames}",
        Modifier.padding(horizontal = 6.dp),
        fontSize = 13.sp,
    )
    Spacer(Modifier.height(17.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Pill(
            "Putar",
            play,
            Modifier.weight(1f),
            filled = true,
            enabled =
                playback.phase in
                    setOf(PlaybackPhase.PREPARED, PlaybackPhase.PAUSED, PlaybackPhase.COMPLETED),
        )
        Pill("Jeda", pause, Modifier.weight(1f), enabled = playback.phase == PlaybackPhase.PLAYING)
        Pill("Tutup", close, Modifier.weight(1f), enabled = playback.phase != PlaybackPhase.IDLE)
    }
    playback.errorCode?.let {
        Text("Pemutaran belum berhasil: $it", color = MaterialTheme.colorScheme.error)
    }
}
