package id.swaralara.core

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity data class LocalRecording(@PrimaryKey val id: String, val kind: String,
    val startedAtDevice: Long, val captureState: String = "STARTING",
    val syncState: String = "LOCAL_ONLY", val recoveryState: String = "LOCAL_ONLY",
    val integrityState: String = "UNVERIFIED", val sampleRate: Int = 16000, val channels: Int = 1,
    val durationSamples: Long = 0, val segmentCount: Int = 0, val policyCode: String = "demo_2of3")
@Entity(primaryKeys = ["recordingId", "segmentIndex"], foreignKeys = [ForeignKey(
    entity = LocalRecording::class, parentColumns = ["id"], childColumns = ["recordingId"])])
data class LocalSegment(val recordingId: String, val segmentIndex: Long, val path: String,
    val ciphertextSha256: String, val previousSha256: String, val byteLength: Long, val samples: Int,
    val uploadedAt: Long? = null)
@Entity(foreignKeys = [ForeignKey(entity = LocalRecording::class, parentColumns = ["id"], childColumns = ["recordingId"])])
data class LocalKeyEnvelope(@PrimaryKey val recordingId: String, val wrappedPayload: ByteArray,
    val envelopeKind: String = "local_dek_v1")
// M2/M3 tables are deliberately not invented here; add them with tested Room migrations when used.
@Dao internal interface LocalDao {
    @Query("SELECT * FROM LocalRecording ORDER BY startedAtDevice DESC") fun observe(): Flow<List<LocalRecording>>
    @Query("SELECT * FROM LocalRecording") suspend fun recordings(): List<LocalRecording>
    @Query("SELECT * FROM LocalRecording WHERE id=:id") suspend fun recording(id: String): LocalRecording?
    @Insert suspend fun insert(recording: LocalRecording)
    @Update suspend fun update(recording: LocalRecording)
    @Insert suspend fun key(key: LocalKeyEnvelope)
    @Query("SELECT * FROM LocalKeyEnvelope WHERE recordingId=:id") suspend fun key(id: String): LocalKeyEnvelope?
    @Insert suspend fun segment(segment: LocalSegment)
    @Query("SELECT * FROM LocalSegment WHERE recordingId=:id ORDER BY segmentIndex") suspend fun segments(id: String): List<LocalSegment>
    @Query("UPDATE LocalRecording SET integrityState=:state WHERE id=:id") suspend fun integrity(id: String, state: String)
}
@Database(entities = [LocalRecording::class, LocalSegment::class, LocalKeyEnvelope::class], version = 1, exportSchema = true)
internal abstract class LocalDatabase : RoomDatabase() { abstract fun dao(): LocalDao }
