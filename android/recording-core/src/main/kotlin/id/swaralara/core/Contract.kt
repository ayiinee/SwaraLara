package id.swaralara.core

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import java.io.File
import java.util.UUID

enum class CaptureState { IDLE, STARTING, RECORDING, STOPPING, SEALED, INTERRUPTED, FAILED }
enum class SyncState { LOCAL_ONLY, QUEUED, PARTIAL, SYNCED, FAILED, NEEDS_AUTH }
enum class RecoveryState { LOCAL_ONLY, DEGRADED }
enum class IntegrityState { UNVERIFIED, VERIFIED_PARTIAL, FAILED }
data class CaptureConfig(val kind: String = "retrospective", val cloudPolicy: CloudCapturePolicy? = null) {
    init { require(kind in setOf("retrospective", "live_event")) }
}
data class RecorderState(val capture: CaptureState = CaptureState.IDLE, val id: UUID? = null,
    val frames: Long = 0, val savedSegments: Int = 0, val encryptedBytes: Long = 0,
    val sampleRate: Int = 16000, val errorCode: String? = null) {
    val busy get() = capture in setOf(CaptureState.STARTING, CaptureState.RECORDING, CaptureState.STOPPING)
}
data class RecordingSummary(val id: UUID, val kind: String, val startedAtDevice: Long,
    val frames: Long, val sampleRate: Int, val segmentCount: Int, val capture: CaptureState,
    val sync: SyncState, val recovery: RecoveryState, val integrity: IntegrityState)
data class StopResult(val id: UUID?, val capture: CaptureState)
data class IntegrityReport(val passed: Boolean, val segments: Int, val frames: Long, val message: String)
data class EncryptedSegmentRef(val recordingId: UUID, val index: Long, val file: File,
    val objectHash: String, val previousHash: String, val byteLength: Long, val sampleCount: Int)
data class EncryptedRecordingSnapshot(val recordingId: UUID, val policyCode: String,
    val formatVersion: Int = 1, val segments: List<EncryptedSegmentRef>, val totalFrames: Long,
    val finalCapture: CaptureState, val signedManifestAvailable: Boolean = false,
    val cloudRegistrationJson: String? = null, val cloudOwnerUserId: UUID? = null)
data class UploadReceipt(val recordingId: UUID, val index: Long, val objectHash: String, val committedAtServer: Long)
data class DemoRecoveryResult(val passed: Boolean, val pairsVerified: Int, val message: String)
enum class PlaybackPhase { IDLE, PREPARING, PREPARED, PLAYING, PAUSED, COMPLETED, FAILED }
data class PlaybackState(val phase: PlaybackPhase = PlaybackPhase.IDLE, val positionFrames: Long = 0,
    val totalFrames: Long = 0, val errorCode: String? = null)
interface RecorderController {
    val state: StateFlow<RecorderState>
    suspend fun start(config: CaptureConfig = CaptureConfig()): UUID
    suspend fun stop(): StopResult
}
interface SecureVault {
    fun observeRecordings(): Flow<List<RecordingSummary>>
    suspend fun inspect(recordingId: UUID): IntegrityReport
    suspend fun exportEncryptedSnapshot(recordingId: UUID): EncryptedRecordingSnapshot
    suspend fun acknowledgeUpload(receipt: UploadReceipt)
    suspend fun markSyncFailure(recordingId: UUID, errorCode: String)
    suspend fun demonstrateRecovery(recordingId: UUID): DemoRecoveryResult
    suspend fun testCorruptionOnCopy(recordingId: UUID): Boolean
}
interface SecurePlaybackController {
    val state: StateFlow<PlaybackState>
    suspend fun prepare(recordingId: UUID): Boolean
    suspend fun play()
    suspend fun pause()
    suspend fun release()
}
