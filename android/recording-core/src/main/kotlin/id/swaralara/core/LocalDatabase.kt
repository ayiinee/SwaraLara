package id.swaralara.core

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity
data class LocalRecording(
    @PrimaryKey val id: String,
    val kind: String,
    val startedAtDevice: Long,
    val captureState: String = "STARTING",
    val syncState: String = "LOCAL_ONLY",
    val recoveryState: String = "LOCAL_ONLY",
    val integrityState: String = "UNVERIFIED",
    val sampleRate: Int = 16000,
    val channels: Int = 1,
    val durationSamples: Long = 0,
    val segmentCount: Int = 0,
    val policyCode: String = "demo_2of3",
)

@Entity(
    primaryKeys = ["recordingId", "segmentIndex"],
    foreignKeys =
        [
            ForeignKey(
                entity = LocalRecording::class,
                parentColumns = ["id"],
                childColumns = ["recordingId"],
            )
        ],
)
data class LocalSegment(
    val recordingId: String,
    val segmentIndex: Long,
    val path: String,
    val ciphertextSha256: String,
    val previousSha256: String,
    val byteLength: Long,
    val samples: Int,
    val uploadedAt: Long? = null,
)

@Entity(
    foreignKeys =
        [
            ForeignKey(
                entity = LocalRecording::class,
                parentColumns = ["id"],
                childColumns = ["recordingId"],
            )
        ]
)
data class LocalKeyEnvelope(
    @PrimaryKey val recordingId: String,
    val wrappedPayload: ByteArray,
    val envelopeKind: String = "local_dek_v1",
)

@Entity
data class LocalCloudRegistration(
    @PrimaryKey val recordingId: String,
    val ownerUserId: String,
    val policyJson: String,
    val snapshotBase64: String,
    val signatureBase64: String,
    val registrationJson: String? = null,
)

@Entity(primaryKeys = ["recordingId", "segmentIndex"])
data class LocalOutbox(
    val recordingId: String,
    val segmentIndex: Long,
    val objectHash: String,
    val state: String = "QUEUED",
    val attempt: Int = 0,
    val lastErrorCode: String? = null,
)

@Entity
data class LocalTrustedDevice(
    @PrimaryKey val deviceId: String,
    val userId: String,
    val hpkePublicBase64: String,
    val signingSpkiBase64: String,
    val hpkeFingerprint: String,
    val signingFingerprint: String,
)

@Entity(primaryKeys = ["recordingId", "shareIndex", "direction"])
data class LocalShareEnvelope(
    val recordingId: String,
    val shareIndex: Int,
    val direction: String,
    val packetJson: String,
    val policyJson: String,
    val uploadedAt: Long? = null,
    val acknowledgmentJson: String? = null,
)

@Entity
data class LocalM3Request(
    @PrimaryKey val requestId: String,
    val recordingId: String,
    val packetJson: String,
    val wrappedPrivateKey: ByteArray,
    val expiresAt: Long,
    val state: String = "PENDING",
)

@Entity(primaryKeys = ["requestId", "shareIndex"])
data class LocalM3Release(val requestId: String, val shareIndex: Int, val packetJson: String)

@Entity data class LocalM3Cancellation(@PrimaryKey val requestId: String, val packetJson: String)

@Entity
data class LocalKeyRetirement(
    @PrimaryKey val recordingId: String,
    val policyHash: String,
    val retiredAt: Long,
)

@Dao
internal interface LocalDao {
    @Query("SELECT * FROM LocalRecording ORDER BY startedAtDevice DESC")
    fun observe(): Flow<List<LocalRecording>>

    @Query("SELECT * FROM LocalRecording") suspend fun recordings(): List<LocalRecording>

    @Query("SELECT * FROM LocalRecording WHERE id=:id")
    suspend fun recording(id: String): LocalRecording?

    @Insert suspend fun insert(recording: LocalRecording)

    @Update suspend fun update(recording: LocalRecording)

    @Insert suspend fun key(key: LocalKeyEnvelope)

    @Query("SELECT * FROM LocalKeyEnvelope WHERE recordingId=:id")
    suspend fun key(id: String): LocalKeyEnvelope?

    @Insert suspend fun segment(segment: LocalSegment)

    @Query("SELECT * FROM LocalSegment WHERE recordingId=:id ORDER BY segmentIndex")
    suspend fun segments(id: String): List<LocalSegment>

    @Query("UPDATE LocalRecording SET integrityState=:state WHERE id=:id")
    suspend fun integrity(id: String, state: String)

    @Insert suspend fun cloud(registration: LocalCloudRegistration)

    @Query("SELECT * FROM LocalCloudRegistration WHERE recordingId=:id")
    suspend fun cloud(id: String): LocalCloudRegistration?

    @Query(
        "UPDATE LocalCloudRegistration SET registrationJson=:json WHERE recordingId=:id AND registrationJson IS NULL"
    )
    suspend fun registration(id: String, json: String)

    @Insert suspend fun outbox(outbox: LocalOutbox)

    @Query("UPDATE LocalSegment SET uploadedAt=:time WHERE recordingId=:id AND segmentIndex=:index")
    suspend fun receipt(id: String, index: Long, time: Long)

    @Query(
        "UPDATE LocalOutbox SET state='COMMITTED',lastErrorCode=NULL WHERE recordingId=:id AND segmentIndex=:index"
    )
    suspend fun committed(id: String, index: Long)

    @Query(
        "UPDATE LocalOutbox SET state=:state,attempt=attempt+1,lastErrorCode=:code WHERE recordingId=:id AND state<>'COMMITTED'"
    )
    suspend fun failure(id: String, state: String, code: String)

    @Insert suspend fun trusted(device: LocalTrustedDevice)

    @Query("SELECT * FROM LocalTrustedDevice WHERE deviceId=:id")
    suspend fun trusted(id: String): LocalTrustedDevice?

    @Insert suspend fun share(envelope: LocalShareEnvelope)

    @Query(
        "SELECT * FROM LocalShareEnvelope WHERE recordingId=:id AND direction=:direction ORDER BY shareIndex"
    )
    suspend fun shares(id: String, direction: String): List<LocalShareEnvelope>

    @Query(
        "UPDATE LocalShareEnvelope SET uploadedAt=:at WHERE recordingId=:id AND shareIndex=:index AND direction='OUTBOUND'"
    )
    suspend fun shareUploaded(id: String, index: Int, at: Long)

    @Query(
        "UPDATE LocalShareEnvelope SET acknowledgmentJson=:json WHERE recordingId=:id AND shareIndex=:index AND direction=:direction"
    )
    suspend fun shareAck(id: String, index: Int, direction: String, json: String)

    @Insert suspend fun request(request: LocalM3Request)

    @Query("SELECT * FROM LocalM3Request WHERE requestId=:id")
    suspend fun request(id: String): LocalM3Request?

    @Query("SELECT * FROM LocalM3Request WHERE state IN ('PENDING','OPEN') ORDER BY expiresAt DESC")
    suspend fun pendingRequests(): List<LocalM3Request>

    @Query("SELECT requestId FROM LocalM3Request WHERE state NOT IN ('PENDING','OPEN')")
    suspend fun closedRequests(): List<String>

    @Query("SELECT requestId FROM LocalM3Request") suspend fun requestIds(): List<String>

    @Query("UPDATE LocalM3Request SET state=:state WHERE requestId=:id")
    suspend fun requestState(id: String, state: String)

    @Query("UPDATE LocalM3Request SET state=:state,wrappedPrivateKey=X'' WHERE requestId=:id")
    suspend fun closeRequest(id: String, state: String)

    @Query(
        "UPDATE LocalM3Request SET state='EXPIRED',wrappedPrivateKey=X'' WHERE expiresAt<=:now AND state IN ('PENDING','OPEN')"
    )
    suspend fun expireRequests(now: Long)

    @Query("UPDATE LocalM3Request SET state='CLOSED',wrappedPrivateKey=X'' WHERE state='OPEN'")
    suspend fun closeOpenRequests()

    @Insert suspend fun release(release: LocalM3Release)

    @Query("SELECT * FROM LocalM3Release WHERE requestId=:id AND shareIndex=:index")
    suspend fun release(id: String, index: Int): LocalM3Release?

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun cancellation(cancellation: LocalM3Cancellation)

    @Query("SELECT * FROM LocalM3Cancellation WHERE requestId=:id")
    suspend fun cancellation(id: String): LocalM3Cancellation?

    @Query("SELECT * FROM LocalM3Cancellation")
    suspend fun cancellations(): List<LocalM3Cancellation>

    @Insert suspend fun retirement(retirement: LocalKeyRetirement)

    @Query("SELECT * FROM LocalKeyRetirement WHERE recordingId=:id")
    suspend fun retirement(id: String): LocalKeyRetirement?

    @Query("DELETE FROM LocalKeyEnvelope WHERE recordingId=:id") suspend fun deleteKey(id: String)
}

@Database(
    entities =
        [
            LocalRecording::class,
            LocalSegment::class,
            LocalKeyEnvelope::class,
            LocalCloudRegistration::class,
            LocalOutbox::class,
            LocalTrustedDevice::class,
            LocalShareEnvelope::class,
            LocalM3Request::class,
            LocalM3Release::class,
            LocalM3Cancellation::class,
            LocalKeyRetirement::class,
        ],
    version = 3,
    exportSchema = true,
)
internal abstract class LocalDatabase : RoomDatabase() {
    abstract fun dao(): LocalDao
}

internal val MIGRATION_1_2 =
    object : androidx.room.migration.Migration(1, 2) {
        override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalCloudRegistration (recordingId TEXT NOT NULL PRIMARY KEY, ownerUserId TEXT NOT NULL, policyJson TEXT NOT NULL, snapshotBase64 TEXT NOT NULL, signatureBase64 TEXT NOT NULL, registrationJson TEXT)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalOutbox (recordingId TEXT NOT NULL, segmentIndex INTEGER NOT NULL, objectHash TEXT NOT NULL, state TEXT NOT NULL, attempt INTEGER NOT NULL, lastErrorCode TEXT, PRIMARY KEY(recordingId,segmentIndex))"
            )
        }
    }

internal val MIGRATION_2_3 =
    object : androidx.room.migration.Migration(2, 3) {
        override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalTrustedDevice (deviceId TEXT NOT NULL PRIMARY KEY,userId TEXT NOT NULL,hpkePublicBase64 TEXT NOT NULL,signingSpkiBase64 TEXT NOT NULL,hpkeFingerprint TEXT NOT NULL,signingFingerprint TEXT NOT NULL)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalShareEnvelope (recordingId TEXT NOT NULL,shareIndex INTEGER NOT NULL,direction TEXT NOT NULL,packetJson TEXT NOT NULL,policyJson TEXT NOT NULL,uploadedAt INTEGER,acknowledgmentJson TEXT,PRIMARY KEY(recordingId,shareIndex,direction))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalM3Request (requestId TEXT NOT NULL PRIMARY KEY,recordingId TEXT NOT NULL,packetJson TEXT NOT NULL,wrappedPrivateKey BLOB NOT NULL,expiresAt INTEGER NOT NULL,state TEXT NOT NULL)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalM3Release (requestId TEXT NOT NULL,shareIndex INTEGER NOT NULL,packetJson TEXT NOT NULL,PRIMARY KEY(requestId,shareIndex))"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalM3Cancellation (requestId TEXT NOT NULL PRIMARY KEY,packetJson TEXT NOT NULL)"
            )
            db.execSQL(
                "CREATE TABLE IF NOT EXISTS LocalKeyRetirement (recordingId TEXT NOT NULL PRIMARY KEY,policyHash TEXT NOT NULL,retiredAt INTEGER NOT NULL)"
            )
        }
    }
