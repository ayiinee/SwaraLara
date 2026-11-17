package id.swaralara.core

import android.media.*
import id.swaralara.crypto.Segments
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID

internal class LocalPlayback(private val vault: LocalVault, private val scope: CoroutineScope,
    private val ready: Deferred<Unit>, private val canPlay: () -> Boolean) : SecurePlaybackController {
    private val mutable = MutableStateFlow(PlaybackState())
    override val state = mutable.asStateFlow()
    private var id: UUID? = null
    private var job: Job? = null
    private val controls = Mutex()
    @Volatile private var track: AudioTrack? = null
    override suspend fun prepare(recordingId: UUID): Boolean = controls.withLock {
        if (!canPlay()) return@withLock false
        releaseLocked(); ready.await()
        mutable.value = PlaybackState(PlaybackPhase.PREPARING)
        val report = vault.inspect(recordingId)
        if (!report.passed) { mutable.value = PlaybackState(PlaybackPhase.FAILED,errorCode = "VERIFICATION_OR_KEY_FAILED"); return@withLock false }
        id = recordingId
        mutable.value = PlaybackState(PlaybackPhase.PREPARED,totalFrames = report.frames)
        true
    }
    override suspend fun play(): Unit = controls.withLock {
        if (!canPlay()) return@withLock
        if (state.value.phase == PlaybackPhase.PAUSED) {
            track?.play(); mutable.update { it.copy(phase = PlaybackPhase.PLAYING) }; return@withLock
        }
        if (state.value.phase !in setOf(PlaybackPhase.PREPARED,PlaybackPhase.COMPLETED) || job?.isActive == true) return@withLock
        val recordingId = id ?: return@withLock
        mutable.value = state.value.copy(phase = PlaybackPhase.PLAYING,positionFrames = 0)
        job = scope.launch {
            try {
                val rec = vault.recording(recordingId)
                val min = AudioTrack.getMinBufferSize(rec.sampleRate,AudioFormat.CHANNEL_OUT_MONO,AudioFormat.ENCODING_PCM_16BIT)
                check(min > 0)
                val output = AudioTrack.Builder().setAudioAttributes(AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
                    .setAudioFormat(AudioFormat.Builder().setSampleRate(rec.sampleRate)
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build())
                    .setTransferMode(AudioTrack.MODE_STREAM).setBufferSizeInBytes(maxOf(min,8192)).build()
                track = output
                check(output.state == AudioTrack.STATE_INITIALIZED)
                output.play()
                vault.withKey(recordingId) { key ->
                    var previous = ByteArray(32)
                    for ((i,segment) in vault.segments(recordingId).withIndex()) {
                        ensureActive()
                        val bytes = vault.read(segment)
                        val pcm = Segments.decryptVerified(key,bytes,recordingId,i.toLong(),previous)
                        try {
                            var offset = 0
                            while (offset < pcm.size) {
                                ensureActive()
                                if (state.value.phase == PlaybackPhase.PAUSED) { delay(20); continue }
                                val written = output.write(pcm,offset,pcm.size-offset,AudioTrack.WRITE_NON_BLOCKING)
                                check(written >= 0) { "PLAYBACK_WRITE" }
                                offset += written
                                mutable.update { it.copy(positionFrames = output.playbackHeadPosition.toLong().and(0xffff_ffffL)) }
                                if (written == 0) delay(10)
                            }
                        } finally { pcm.fill(0) }
                        previous = Segments.hash(bytes)
                    }
                }
                while (output.playbackHeadPosition.toLong().and(0xffff_ffffL) < state.value.totalFrames) {
                    ensureActive(); delay(20)
                    mutable.update { it.copy(positionFrames = output.playbackHeadPosition.toLong().and(0xffff_ffffL)) }
                }
                mutable.value = state.value.copy(phase = PlaybackPhase.COMPLETED,positionFrames = state.value.totalFrames)
            } catch (e: CancellationException) { throw e }
            catch (_: Exception) { mutable.value = state.value.copy(phase = PlaybackPhase.FAILED,errorCode = "PLAYBACK_OR_VERIFICATION_FAILED") }
            finally { track?.release(); track = null }
        }
    }
    override suspend fun pause(): Unit = controls.withLock {
        if (state.value.phase == PlaybackPhase.PLAYING) {
            mutable.update { it.copy(phase = PlaybackPhase.PAUSED) }
            try { track?.pause() } catch (_: IllegalStateException) {
                releaseLocked(); mutable.value = PlaybackState(PlaybackPhase.FAILED,errorCode = "PLAYBACK_PAUSE_FAILED")
            }
        }
    }
    override suspend fun release(): Unit = controls.withLock { releaseLocked() }
    private suspend fun releaseLocked() {
        job?.cancelAndJoin(); job = null; id = null
        mutable.value = PlaybackState()
    }
}
