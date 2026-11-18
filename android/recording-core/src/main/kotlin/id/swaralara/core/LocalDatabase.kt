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
@Entity data class LocalCloudRegistration(@PrimaryKey val recordingId: String,val ownerUserId: String,
    val policyJson: String,val snapshotBase64: String,val signatureBase64: String,val registrationJson: String? = null)
@Entity(primaryKeys=["recordingId","segmentIndex"])
data class LocalOutbox(val recordingId: String,val segmentIndex: Long,val objectHash: String,
    val state: String = "QUEUED",val attempt: Int = 0,val lastErrorCode: String? = null)
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
    @Insert suspend fun cloud(registration: LocalCloudRegistration)
    @Query("SELECT * FROM LocalCloudRegistration WHERE recordingId=:id") suspend fun cloud(id: String): LocalCloudRegistration?
    @Query("UPDATE LocalCloudRegistration SET registrationJson=:json WHERE recordingId=:id AND registrationJson IS NULL") suspend fun registration(id: String,json: String)
    @Insert suspend fun outbox(outbox: LocalOutbox)
    @Query("UPDATE LocalSegment SET uploadedAt=:time WHERE recordingId=:id AND segmentIndex=:index") suspend fun receipt(id: String,index: Long,time: Long)
    @Query("UPDATE LocalOutbox SET state='COMMITTED',lastErrorCode=NULL WHERE recordingId=:id AND segmentIndex=:index") suspend fun committed(id: String,index: Long)
    @Query("UPDATE LocalOutbox SET state=:state,attempt=attempt+1,lastErrorCode=:code WHERE recordingId=:id AND state<>'COMMITTED'") suspend fun failure(id: String,state: String,code: String)
}
@Database(entities = [LocalRecording::class, LocalSegment::class, LocalKeyEnvelope::class,LocalCloudRegistration::class,LocalOutbox::class], version = 2, exportSchema = true)
internal abstract class LocalDatabase : RoomDatabase() { abstract fun dao(): LocalDao }

internal val MIGRATION_1_2=object:androidx.room.migration.Migration(1,2){
    override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
        db.execSQL("CREATE TABLE IF NOT EXISTS LocalCloudRegistration (recordingId TEXT NOT NULL PRIMARY KEY, ownerUserId TEXT NOT NULL, policyJson TEXT NOT NULL, snapshotBase64 TEXT NOT NULL, signatureBase64 TEXT NOT NULL, registrationJson TEXT)")
        db.execSQL("CREATE TABLE IF NOT EXISTS LocalOutbox (recordingId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, objectHash TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL, lastErrorCode TEXT, PRIMARY KEY(recordingId,segmentIndex))")
    }
}
