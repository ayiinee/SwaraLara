package id.swaralara.core

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Context
import id.swaralara.crypto.Segments
import kotlinx.coroutines.*
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class LocalVaultTest {
    private lateinit var db: LocalDatabase
    private lateinit var root: File
    private lateinit var vault: LocalVault
    @Before fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        root = File(context.filesDir,"vault-test-${UUID.randomUUID()}")
        check(root.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
        db = Room.inMemoryDatabaseBuilder(context,LocalDatabase::class.java).build()
        vault = LocalVault(root,db,KeyProtector())
    }
    @After fun teardown() { db.close(); root.deleteRecursively() }
    private suspend fun capture(): UUID {
        val id = UUID.randomUUID()
        vault.create(id,CaptureConfig(),16000).use { session ->
            vault.capture(id,CaptureState.RECORDING)
            vault.persist(id,session.encrypt(ByteArray(64000) { (it % 91).toByte() }))
            vault.persist(id,session.encrypt(ByteArray(222) { (it % 7).toByte() }))
        }
        vault.capture(id,CaptureState.SEALED)
        return id
    }
    @Test fun localRoundTripRecoverySnapshotAndCorruption() = runBlocking {
        val id = capture()
        val report = vault.inspect(id)
        assertTrue(report.passed); assertEquals(32111L,report.frames)
        assertEquals(3,vault.demonstrateRecovery(id).pairsVerified)
        val snapshot = vault.exportEncryptedSnapshot(id)
        val before = snapshot.segments.map { it.file.readBytes() }
        assertTrue(vault.testCorruptionOnCopy(id))
        snapshot.segments.forEachIndexed { i, s -> assertArrayEquals(before[i],s.file.readBytes()) }
        assertTrue(vault.inspect(id).passed)
        try { vault.acknowledgeUpload(UploadReceipt(id,0,snapshot.segments[0].objectHash,1)); fail("Demo cloud ack accepted") }
        catch (_: IllegalStateException) { }
        assertFalse(snapshot.signedManifestAvailable)
    }
    @Test fun finalFileSurvivesCrashBeforeIndexAndPartialTmpRemoved() = runBlocking {
        val id = capture()
        db.openHelper.writableDatabase.execSQL("DELETE FROM LocalSegment WHERE recordingId=? AND segmentIndex=1", arrayOf(id.toString()))
        val rec = vault.recording(id)
        db.dao().update(rec.copy(captureState = "RECORDING",durationSamples = 32000,segmentCount = 1))
        val tmp = File(root,"$id/segments/2.tmp").apply { writeBytes(byteArrayOf(1,2,3)) }
        vault.reconcile()
        assertFalse(tmp.exists())
        assertEquals("INTERRUPTED",vault.recording(id).captureState)
        assertEquals(2,vault.segments(id).size)
        assertEquals(32111L,vault.recording(id).durationSamples)
        assertTrue(vault.inspect(id).passed)
    }
    @Test fun modifiedIndexedObjectCannotBeBlessedByReconciliation() = runBlocking {
        val id = capture()
        val segment = vault.segments(id).first()
        val bytes = File(segment.path).readBytes()
        bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
        File(segment.path).writeBytes(bytes)
        vault.reconcile()
        assertEquals("FAILED",vault.recording(id).integrityState)
        assertFalse(vault.inspect(id).passed)
        assertEquals(segment.ciphertextSha256,vault.segments(id).first().ciphertextSha256)
        assertTrue(File(segment.path).exists())
    }
    @Test fun missingTailRejectedAgainstLocalIndex() = runBlocking {
        val id = capture()
        File(vault.segments(id).last().path).delete()
        vault.reconcile()
        assertFalse(vault.inspect(id).passed)
        assertEquals(2,vault.segments(id).size)
    }
    @Test fun immutableSegmentRetryAndKeystoreBinding() = runBlocking {
        val id = capture()
        val segment = vault.segments(id).first()
        val bytes = File(segment.path).readBytes()
        try { vault.persist(id,bytes); fail("Overwrote immutable segment") } catch (_: IllegalStateException) { }
        assertArrayEquals(bytes,File(segment.path).readBytes())
        val key = ByteArray(32) { it.toByte() }
        val protector = KeyProtector()
        val wrapped = protector.wrap(id.toString(),key)
        assertArrayEquals(key,protector.unwrap(id.toString(),wrapped))
        try { protector.unwrap(UUID.randomUUID().toString(),wrapped); fail("Accepted wrong binding") }
        catch (_: java.security.GeneralSecurityException) { }
        key.fill(0)
        assertEquals(Segments.hex(Segments.hash(bytes)),segment.ciphertextSha256)
    }
    @Test fun newSessionAfterInterruptionUsesFreshKeyAndNoncePrefix() = runBlocking {
        val first = capture()
        vault.capture(first,CaptureState.RECORDING)
        vault.reconcile()
        assertEquals("INTERRUPTED",vault.recording(first).captureState)
        val second = capture()
        assertNotEquals(first,second)
        val firstObject = File(vault.segments(first).first().path).readBytes()
        val secondObject = File(vault.segments(second).first().path).readBytes()
        assertFalse(Segments.parse(firstObject).nonce.copyOfRange(0,8)
            .contentEquals(Segments.parse(secondObject).nonce.copyOfRange(0,8)))
        vault.withKey(first) { firstKey ->
            vault.withKey(second) { secondKey ->
                assertFalse(java.security.MessageDigest.isEqual(firstKey,secondKey))
                try {
                    Segments.decryptVerified(firstKey,secondObject,second,0,ByteArray(32)).fill(0)
                    fail("Old session key opened new recording")
                } catch (_: javax.crypto.AEADBadTagException) { }
            }
        }
        assertTrue(vault.inspect(first).passed)
        assertTrue(vault.inspect(second).passed)
    }
}
