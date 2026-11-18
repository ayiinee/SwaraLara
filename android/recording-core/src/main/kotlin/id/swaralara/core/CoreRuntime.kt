package id.swaralara.core

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import androidx.room.Room
import java.io.File
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

class CoreRuntime private constructor(context: Context) {
    private val app = context.applicationContext
    internal val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val db =
        Room.databaseBuilder(app, LocalDatabase::class.java, "swaralara-core.db")
            .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
            .build()
    private val protector = KeyProtector()
    val identity = DeviceIdentity(app, protector)
    internal val localVault = LocalVault(File(app.filesDir, "recordings"), db, protector, identity)
    internal val ready = scope.async { localVault.reconcile() }
    internal val localRecorder = LocalRecorder(app, this)
    val recorder: RecorderController = localRecorder
    val vault: SecureVault = localVault
    val keyExchange: SecureKeyExchange = LocalKeyExchange(db, localVault, identity)
    val playback: SecurePlaybackController =
        LocalPlayback(localVault, scope, ready) { !localRecorder.state.value.busy }

    suspend fun awaitReady() {
        ready.await()
    }

    /**
     * Host Activity onStop: release playback buffers/resources; the recording service keeps
     * ownership of capture.
     */
    fun onHostBackgrounded() {
        scope.launch {
            playback.release()
            keyExchange.closeOpenSessions()
        }
    }

    companion object {
        @Volatile private var instance: CoreRuntime? = null

        fun get(context: Context): CoreRuntime =
            instance
                ?: synchronized(this) { instance ?: CoreRuntime(context).also { instance = it } }
    }
}

internal class LocalRecorder(private val app: Context, private val core: CoreRuntime) :
    RecorderController {
    private val mutable = MutableStateFlow(RecorderState())
    override val state = mutable.asStateFlow()
    private val mutex = Mutex()

    internal fun publish(state: RecorderState) {
        mutable.value = state
    }

    internal fun fail(code: String) {
        mutable.value = mutable.value.copy(capture = CaptureState.FAILED, errorCode = code)
    }

    override suspend fun start(config: CaptureConfig): UUID =
        mutex.withLock {
            try {
                core.ready.await()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                fail("LOCAL_STORAGE_UNAVAILABLE")
                throw e
            }
            check(!mutable.value.busy) { "RECORDER_BUSY" }
            check(
                core.playback.state.value.phase !in
                    setOf(PlaybackPhase.PLAYING, PlaybackPhase.PAUSED)
            ) {
                "PLAYBACK_BUSY"
            }
            if (
                ContextCompat.checkSelfPermission(app, Manifest.permission.RECORD_AUDIO) !=
                    PackageManager.PERMISSION_GRANTED
            ) {
                fail("MIC_PERMISSION")
                error("MIC_PERMISSION")
            }
            val id = UUID.randomUUID()
            mutable.value = RecorderState(CaptureState.STARTING, id)
            try {
                ContextCompat.startForegroundService(
                    app,
                    Intent(app, RecordingService::class.java)
                        .setAction(RecordingService.START)
                        .putExtra("id", id.toString())
                        .putExtra("kind", config.kind)
                        .putExtra("cloudPolicy", config.cloudPolicy?.json()),
                )
            } catch (e: Exception) {
                fail("SERVICE_START_FAILED")
                throw e
            }
            id
        }

    override suspend fun stop(): StopResult {
        if (state.value.busy) {
            app.startService(
                Intent(app, RecordingService::class.java).setAction(RecordingService.STOP)
            )
            withTimeout(15_000) { state.first { !it.busy } }
        }
        return StopResult(state.value.id, state.value.capture)
    }
}
