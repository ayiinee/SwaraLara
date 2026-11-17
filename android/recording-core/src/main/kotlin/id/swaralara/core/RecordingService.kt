package id.swaralara.core

import android.app.*
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.*
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import id.swaralara.crypto.PcmSegmenter
import id.swaralara.crypto.SegmentSession
import kotlinx.coroutines.*
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

class RecordingService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var job: Job? = null
    private val stopping = AtomicBoolean(false)
    @Volatile private var audio: AudioRecord? = null
    private lateinit var core: CoreRuntime
    override fun onCreate() { super.onCreate(); core = CoreRuntime.get(this) }
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            stopping.set(true)
            try { audio?.stop() } catch (_: IllegalStateException) { }
            if (job == null) { core.localRecorder.publish(core.recorder.state.value.copy(capture = CaptureState.INTERRUPTED)); stopSelf() }
            return START_NOT_STICKY
        }
        if (intent?.action != START || job?.isActive == true) return START_NOT_STICKY
        try {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL,"Perekaman lokal",NotificationManager.IMPORTANCE_LOW))
            val stop = PendingIntent.getService(this,0,Intent(this,RecordingService::class.java).setAction(STOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val notification = NotificationCompat.Builder(this,CHANNEL)
                .setSmallIcon(android.R.drawable.ic_btn_speak_now).setContentTitle("SwaraLara — mikrofon aktif")
                .setContentText("Perekaman lokal sedang disiapkan / berlangsung")
                .setOngoing(true).addAction(0,"Hentikan",stop).build()
            ServiceCompat.startForeground(this,41,notification,
                if (Build.VERSION.SDK_INT >= 30) ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE else 0)
        } catch (_: Exception) { core.localRecorder.fail("FOREGROUND_PERMISSION"); stopSelf(); return START_NOT_STICKY }
        val id = try { UUID.fromString(intent.getStringExtra("id")) }
        catch (_: Exception) { core.localRecorder.fail("INVALID_SESSION"); stopSelf(); return START_NOT_STICKY }
        val config = CaptureConfig(intent.getStringExtra("kind") ?: "retrospective")
        stopping.set(false)
        job = scope.launch { record(id,config,startId) }
        return START_NOT_STICKY // Never reuse a session/key/counter after process death.
    }
    @android.annotation.SuppressLint("MissingPermission")
    private suspend fun record(id: UUID, config: CaptureConfig, startId: Int) {
        var session: SegmentSession? = null
        var segmenter: PcmSegmenter? = null
        val readBuffer = ByteArray(8192)
        var finalState = CaptureState.FAILED
        var error: String? = null
        try {
            core.ready.await()
            val rate = listOf(16000,48000,44100).firstOrNull {
                AudioRecord.getMinBufferSize(it,AudioFormat.CHANNEL_IN_MONO,AudioFormat.ENCODING_PCM_16BIT) > 0
            } ?: error("AUDIO_UNSUPPORTED")
            val minimum = AudioRecord.getMinBufferSize(rate,AudioFormat.CHANNEL_IN_MONO,AudioFormat.ENCODING_PCM_16BIT)
            val recorder = AudioRecord.Builder().setAudioSource(MediaRecorder.AudioSource.MIC)
                .setAudioFormat(AudioFormat.Builder().setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(rate).setChannelMask(AudioFormat.CHANNEL_IN_MONO).build())
                .setBufferSizeInBytes(maxOf(minimum * 2,8192)).build()
            audio = recorder
            check(recorder.state == AudioRecord.STATE_INITIALIZED) { "MIC_INIT" }
            session = core.localVault.create(id,config,rate)
            val encryptor = session
            var frames = 0L; var count = 0; var encrypted = 0L
            segmenter = PcmSegmenter(rate * 2 * 2) { pcm ->
                val bytes = encryptor.encrypt(pcm)
                runBlocking { core.localVault.persist(id,bytes) }
                frames += pcm.size / 2; count++; encrypted += bytes.size
                core.localRecorder.publish(RecorderState(if (stopping.get()) CaptureState.STOPPING else CaptureState.RECORDING,
                    id,frames,count,encrypted,rate))
            }
            if (!stopping.get()) {
                recorder.startRecording()
                check(recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) { "MIC_START" }
                core.localVault.capture(id,CaptureState.RECORDING)
                core.localRecorder.publish(RecorderState(CaptureState.RECORDING,id,sampleRate = rate))
            }
            var emptyReads = 0
            while (!stopping.get()) {
                currentCoroutineContext().ensureActive()
                val length = recorder.read(readBuffer,0,readBuffer.size,AudioRecord.READ_BLOCKING)
                if (length > 0) { segmenter.append(readBuffer,length); emptyReads = 0 }
                else if (!stopping.get()) {
                    check(length >= 0) { "MIC_READ" }
                    check(++emptyReads < 100) { "MIC_STALLED" }; delay(10)
                }
                if (Build.VERSION.SDK_INT >= 29) check(recorder.activeRecordingConfiguration?.isClientSilenced != true) { "MIC_SILENCED" }
            }
            core.localRecorder.publish(core.recorder.state.value.copy(capture = CaptureState.STOPPING))
            segmenter.finish()
            finalState = CaptureState.SEALED
        } catch (e: CancellationException) { finalState = CaptureState.INTERRUPTED; error = "SERVICE_INTERRUPTED" }
        catch (_: SecurityException) { error = "MIC_PERMISSION" }
        catch (_: IOException) { error = "STORAGE_WRITE_FAILED" }
        catch (_: Exception) { error = "CAPTURE_FAILED" }
        finally {
            try { audio?.stop() } catch (_: IllegalStateException) { }
            audio?.release(); audio = null
            segmenter?.close(); session?.close(); readBuffer.fill(0)
            withContext(NonCancellable) {
                try { core.localVault.capture(id,finalState) }
                catch (_: Exception) { finalState = CaptureState.FAILED; error = "STORAGE_WRITE_FAILED" }
                withContext(Dispatchers.Main) {
                    // Keep terminal state and service teardown atomic with respect to a new start intent.
                    job = null
                    stopForeground(STOP_FOREGROUND_REMOVE); stopSelfResult(startId)
                    core.localRecorder.publish(core.recorder.state.value.copy(capture = finalState,errorCode = error))
                }
            }
        }
    }
    override fun onDestroy() {
        stopping.set(true)
        try { audio?.stop() } catch (_: IllegalStateException) { }
        scope.cancel(); super.onDestroy()
    }
    companion object { const val START = "id.swaralara.START"; const val STOP = "id.swaralara.STOP"; private const val CHANNEL = "swaralara.recording" }
}
