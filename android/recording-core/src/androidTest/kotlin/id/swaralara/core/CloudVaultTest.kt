package id.swaralara.core

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class CloudVaultTest {
    private val context
        get() = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun versionOneMigrationPreservesRecordingSegmentAndWrappedKey() = runBlocking {
        val name = "migration-${UUID.randomUUID()}.db"
        val path = context.getDatabasePath(name)
        path.parentFile!!.mkdirs()
        val schema =
            InstrumentationRegistry.getInstrumentation()
                .context
                .assets
                .open("id.swaralara.core.LocalDatabase/1.json")
                .bufferedReader()
                .use { JSONObject(it.readText()).getJSONObject("database") }
        val id = UUID.randomUUID().toString()
        SQLiteDatabase.openOrCreateDatabase(path, null).use { old ->
            val entities = schema.getJSONArray("entities")
            for (i in 0 until entities.length()) {
                val entity = entities.getJSONObject(i)
                old.execSQL(
                    entity
                        .getString("createSql")
                        .replace("\${TABLE_NAME}", entity.getString("tableName"))
                )
            }
            val setup = schema.getJSONArray("setupQueries")
            for (i in 0 until setup.length()) old.execSQL(setup.getString(i))
            old.execSQL(
                "INSERT INTO LocalRecording VALUES (?, 'sesi', 10, 'SEALED', 'LOCAL_ONLY', 'LOCAL_ONLY', 'UNVERIFIED', 16000, 1, 2, 1, 'demo_2of3')",
                arrayOf(id),
            )
            old.execSQL(
                "INSERT INTO LocalKeyEnvelope VALUES (?, ?, 'local_dek_v1')",
                arrayOf(id, byteArrayOf(1, 2, 3)),
            )
            old.execSQL(
                "INSERT INTO LocalSegment VALUES (?, 0, '/synthetic/path', ?, ?, 102, 2, NULL)",
                arrayOf(id, "a".repeat(64), "0".repeat(64)),
            )
            old.version = 1
        }
        val upgraded =
            Room.databaseBuilder(context, LocalDatabase::class.java, name)
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build()
        try {
            assertEquals(1, upgraded.dao().recordings().size)
            assertEquals("demo_2of3", upgraded.dao().recording(id)!!.policyCode)
            assertEquals(2L, upgraded.dao().recording(id)!!.durationSamples)
            assertArrayEquals(byteArrayOf(1, 2, 3), upgraded.dao().key(id)!!.wrappedPayload)
            assertNull(upgraded.dao().segments(id).single().uploadedAt)
            assertNull(upgraded.dao().cloud(id))
            upgraded.openHelper.writableDatabase.query("SELECT count(*) FROM LocalOutbox").use {
                assertTrue(it.moveToFirst())
                assertEquals(0, it.getInt(0))
            }
        } finally {
            upgraded.close()
            context.deleteDatabase(name)
        }
    }

    @Test
    fun cloudReceiptRetryKeepsCiphertextIdentityAndLocalKey() = runBlocking {
        val root = File(context.filesDir, "cloud-vault-test-${UUID.randomUUID()}")
        check(root.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
        val db = Room.inMemoryDatabaseBuilder(context, LocalDatabase::class.java).build()
        try {
            val protector = KeyProtector()
            val identity = DeviceIdentity(context, protector)
            val own = identity.publicIdentity()
            assertEquals(own.deviceId, identity.publicIdentity().deviceId)
            assertEquals(own.hpkeFingerprint, identity.publicIdentity().hpkeFingerprint)
            val owner = UUID.randomUUID()
            val policy =
                CloudCapturePolicy(
                    owner,
                    own.deviceId,
                    "owner_required_2of2",
                    listOf(
                        CloudMember(
                            1,
                            owner,
                            own.deviceId,
                            own.hpkeFingerprint,
                            own.signingFingerprint,
                        ),
                        CloudMember(
                            2,
                            UUID.randomUUID(),
                            UUID.randomUUID(),
                            "a".repeat(64),
                            "b".repeat(64),
                        ),
                    ),
                )
            val id = UUID.randomUUID()
            val vault = LocalVault(root, db, protector, identity)
            vault.create(id, CaptureConfig(cloudPolicy = policy), 16000).use { session ->
                vault.capture(id, CaptureState.RECORDING)
                vault.persist(id, session.encrypt(ByteArray(64000)))
                vault.persist(id, session.encrypt(ByteArray(222)))
            }
            vault.capture(id, CaptureState.SEALED)
            val snapshot = vault.exportEncryptedSnapshot(id)
            val bytes = snapshot.segments.map { it.file.readBytes() }
            val envelope = db.dao().key(id.toString())!!.wrappedPayload.copyOf()
            assertNotNull(snapshot.cloudRegistrationJson)
            assertEquals(
                snapshot.cloudRegistrationJson,
                vault.exportEncryptedSnapshot(id).cloudRegistrationJson,
            )
            try {
                vault.acknowledgeUpload(UploadReceipt(id, 0, "0".repeat(64), 1))
                fail("Invalid receipt accepted")
            } catch (_: IllegalArgumentException) {}
            assertEquals("QUEUED", vault.recording(id).syncState)
            for (segment in snapshot.segments) {
                val receipt = UploadReceipt(id, segment.index, segment.objectHash, 123)
                vault.acknowledgeUpload(receipt)
                vault.acknowledgeUpload(receipt)
                if (segment.index == 0L) assertEquals("PARTIAL", vault.recording(id).syncState)
            }
            assertEquals("SYNCED", vault.recording(id).syncState)
            assertEquals("DEGRADED", vault.recording(id).recoveryState)
            assertArrayEquals(envelope, db.dao().key(id.toString())!!.wrappedPayload)
            snapshot.segments.forEachIndexed { i, segment ->
                assertArrayEquals(bytes[i], segment.file.readBytes())
            }
            assertTrue(vault.inspect(id).passed)
        } finally {
            db.dao().recordings().forEach {
                KeyProtector.destroyRecordingKey(UUID.fromString(it.id))
            }
            db.close()
            root.deleteRecursively()
        }
    }
}
