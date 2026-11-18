package id.swaralara.core

import androidx.room.withTransaction
import id.swaralara.crypto.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

internal class LocalVault(private val root: File, private val db: LocalDatabase, private val protector: KeyProtector,
    private val identity: DeviceIdentity? = null) : SecureVault {
    private val dao = db.dao()
    private fun directory(id: UUID) = File(root, "$id/segments").apply {
        if (!mkdirs() && !isDirectory) throw java.io.IOException("STORAGE_DIRECTORY")
    }
    private fun file(id: UUID, index: Long) = File(directory(id), "$index.swseg")
    internal suspend fun create(id: UUID, config: CaptureConfig, rate: Int): SegmentSession {
        val key = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val wrapped = protector.wrap(id.toString(), key)
            val policy=config.cloudPolicy
            val registration=policy?.let {
                val own=requireNotNull(identity).publicIdentity()
                require(it.sourceDeviceId==own.deviceId && it.members.first().signingFingerprint==own.signingFingerprint && it.members.first().hpkeFingerprint==own.hpkeFingerprint)
                val bytes=it.bytes(id)
                LocalCloudRegistration(id.toString(),it.ownerUserId.toString(),it.json(),encodeBase64(bytes),encodeBase64(identity.sign(bytes)))
            }
            db.withTransaction {
                dao.insert(LocalRecording(id.toString(), config.kind, System.currentTimeMillis(), sampleRate = rate,
                    syncState=if(policy==null) "LOCAL_ONLY" else "QUEUED",recoveryState=if(policy==null) "LOCAL_ONLY" else "DEGRADED",
                    policyCode=policy?.policyCode ?: "demo_2of3"))
                dao.key(LocalKeyEnvelope(id.toString(), wrapped))
                if(registration!=null) dao.cloud(registration)
            }
            return SegmentSession(id, key.copyOf(), rate)
        } finally { key.fill(0) }
    }
    internal suspend fun persist(id: UUID, bytes: ByteArray) {
        val h = Segments.parse(bytes)
        require(h.recordingId == id)
        val target = file(id,h.index)
        check(!target.exists()) { "IMMUTABLE_SEGMENT" }
        val tmp = File(target.parentFile, "${h.index}.tmp")
        FileOutputStream(tmp).use { it.write(bytes); it.fd.sync() }
        check(tmp.renameTo(target)) { "ATOMIC_RENAME" }
        db.withTransaction {
            dao.segment(row(target, bytes))
            val rec = requireNotNull(dao.recording(id.toString()))
            if(rec.policyCode!="demo_2of3") dao.outbox(LocalOutbox(id.toString(),h.index,Segments.hex(Segments.hash(bytes))))
            dao.update(rec.copy(durationSamples = rec.durationSamples + h.sampleCount, segmentCount = rec.segmentCount + 1))
        }
    }
    private fun row(target: File, bytes: ByteArray): LocalSegment {
        val h = Segments.parse(bytes)
        return LocalSegment(h.recordingId.toString(),h.index,target.absolutePath,
            Segments.hex(Segments.hash(bytes)),Segments.hex(h.previousObjectHash),bytes.size.toLong(),h.sampleCount)
    }
    internal suspend fun capture(id: UUID, state: CaptureState) {
        dao.recording(id.toString())?.let { dao.update(it.copy(captureState = state.name)) }
    }
    override fun observeRecordings() = dao.observe().map { list -> list.map {
        RecordingSummary(UUID.fromString(it.id),it.kind,it.startedAtDevice,it.durationSamples,it.sampleRate,
            it.segmentCount,CaptureState.valueOf(it.captureState),SyncState.valueOf(it.syncState),
            RecoveryState.valueOf(it.recoveryState),IntegrityState.valueOf(it.integrityState))
    } }
    internal suspend fun <T> withKey(id: UUID, block: suspend (ByteArray) -> T): T {
        val envelope = requireNotNull(dao.key(id.toString())) { "KEY_UNAVAILABLE" }
        val key = protector.unwrap(id.toString(), envelope.wrappedPayload)
        return try { block(key) } finally { key.fill(0) }
    }
    internal suspend fun recording(id: UUID) = requireNotNull(dao.recording(id.toString()))
    internal suspend fun segments(id: UUID) = dao.segments(id.toString())
    internal fun read(segment: LocalSegment): ByteArray {
        val f = File(segment.path)
        require(f.length() == segment.byteLength && f.length() <= Segments.MAX_OBJECT_BYTES)
        val bytes = f.readBytes()
        require(Segments.hex(Segments.hash(bytes)) == segment.ciphertextSha256) { "OBJECT_HASH" }
        return bytes
    }
    internal suspend fun verifyWithKey(id: UUID, key: ByteArray): IntegrityReport {
        val rec = recording(id)
        check(rec.captureState !in setOf("STARTING", "RECORDING", "STOPPING")) { "CAPTURE_ACTIVE" }
        val segments = segments(id)
        require(segments.size == rec.segmentCount && segments.isNotEmpty()) { "SEGMENT_COUNT" }
        val files = directory(id).listFiles { f -> f.extension == "swseg" } ?: emptyArray()
        require(files.size == segments.size) { "UNINDEXED_SEGMENT" }
        var previous = ByteArray(32)
        var frames = 0L
        var prefix: ByteArray? = null
        segments.forEachIndexed { index, segment ->
            require(segment.segmentIndex == index.toLong()) { "ORDER" }
            val bytes = read(segment)
            val h = Segments.parse(bytes)
            require(h.sampleRate == rec.sampleRate && h.sampleCount == segment.samples)
            require(Segments.hex(previous) == segment.previousSha256)
            val currentPrefix = h.nonce.copyOfRange(0,8)
            require(prefix == null || prefix!!.contentEquals(currentPrefix)) { "NONCE_PREFIX" }
            prefix = currentPrefix
            Segments.decryptVerified(key, bytes, id, index.toLong(), previous).fill(0)
            previous = Segments.hash(bytes); frames += h.sampleCount
        }
        require(frames == rec.durationSamples) { "FRAME_COUNT" }
        return IntegrityReport(true, segments.size, frames,
            "Segmen dan frame lolos; manifest bertanda tangan belum tersedia. Kelengkapan akhir belum dibuktikan.")
    }
    override suspend fun inspect(recordingId: UUID): IntegrityReport = withContext(Dispatchers.IO) {
        try {
            val report = withKey(recordingId) { verifyWithKey(recordingId,it) }
            dao.integrity(recordingId.toString(),"VERIFIED_PARTIAL"); report
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            dao.integrity(recordingId.toString(),"FAILED")
            IntegrityReport(false,0,0,"Pemeriksaan gagal: kunci, indeks, atau segmen tidak dapat diverifikasi.")
        }
    }
    override suspend fun demonstrateRecovery(recordingId: UUID): DemoRecoveryResult = withContext(Dispatchers.IO) {
        withKey(recordingId) { original ->
            val shares = DemoSharing.split(recordingId,original)
            var count = 0
            try {
                for ((a,b) in listOf(0 to 1,0 to 2,1 to 2)) {
                    val key = DemoSharing.recover(recordingId,listOf(shares[a],shares[b]))
                    try { check(MessageDigest.isEqual(original,key)); verifyWithKey(recordingId,key); count++ }
                    finally { key.fill(0) }
                }
                DemoRecoveryResult(true,count,"Lulus: 3 pasangan memulihkan kunci dan mengautentikasi audio. Demo algoritma lokal.")
            } finally { shares.forEach { it.clear() } }
        }
    }
    override suspend fun testCorruptionOnCopy(recordingId: UUID): Boolean = withContext(Dispatchers.IO) {
        val segment = segments(recordingId).first()
        val copy = read(segment).copyOf()
        copy[copy.lastIndex] = (copy.last().toInt() xor 1).toByte()
        withKey(recordingId) { key ->
            try { Segments.decryptVerified(key,copy,recordingId,0,ByteArray(32)).fill(0); false }
            catch (_: javax.crypto.AEADBadTagException) { true }
        }
    }
    override suspend fun exportEncryptedSnapshot(recordingId: UUID): EncryptedRecordingSnapshot = withContext(Dispatchers.IO) {
        check(inspect(recordingId).passed) { "INVALID_SNAPSHOT" }
        val rec = recording(recordingId)
        val cloud=dao.cloud(recordingId.toString())
        if(cloud!=null) check(rec.captureState in setOf("SEALED","INTERRUPTED")) { "CLOUD_CAPTURE_NOT_FINAL" }
        val json=cloud?.registrationJson ?: cloud?.let {
            val text=org.json.JSONObject().put("id",recordingId).put("sourceDeviceId",CloudCapturePolicy.fromJson(it.policyJson).sourceDeviceId)
                .put("kind",rec.kind).put("policyCode",rec.policyCode).put("sampleRate",rec.sampleRate).put("channels",1).put("pcmEncoding","pcm16le")
                .put("startedAtDevice",java.time.Instant.ofEpochMilli(rec.startedAtDevice).toString()).put("captureState",rec.captureState.lowercase())
                .put("totalSegments",rec.segmentCount).put("totalSamples",rec.durationSamples).put("policySnapshotBase64",it.snapshotBase64)
                .put("policySignatureBase64",it.signatureBase64).toString()
            dao.registration(recordingId.toString(),text);text
        }
        EncryptedRecordingSnapshot(recordingId,rec.policyCode, segments = segments(recordingId).map {
            EncryptedSegmentRef(recordingId,it.segmentIndex,File(it.path),it.ciphertextSha256,
                it.previousSha256,it.byteLength,it.samples)
        },totalFrames = rec.durationSamples, finalCapture = CaptureState.valueOf(rec.captureState),cloudRegistrationJson=json,
            cloudOwnerUserId=cloud?.ownerUserId?.let(UUID::fromString))
    }
    override suspend fun acknowledgeUpload(receipt: UploadReceipt) = withContext(Dispatchers.IO) {
        db.withTransaction {
            val rec=recording(receipt.recordingId)
            check(rec.policyCode != "demo_2of3" && dao.cloud(rec.id)!=null) { "DEMO_CLOUD_FORBIDDEN" }
            val segment=segments(receipt.recordingId).single { it.segmentIndex==receipt.index }
            require(segment.ciphertextSha256==receipt.objectHash && receipt.committedAtServer>0) { "RECEIPT_BINDING" }
            dao.receipt(rec.id,receipt.index,receipt.committedAtServer);dao.committed(rec.id,receipt.index)
            val synced=segments(receipt.recordingId).all { it.uploadedAt!=null }
            dao.update(rec.copy(syncState=if(synced) "SYNCED" else "PARTIAL"))
            // Full DEK envelope remains. Sync is not holder acknowledgment or threshold recovery.
        }
    }
    override suspend fun markSyncFailure(recordingId: UUID,errorCode: String) = withContext(Dispatchers.IO) {
        require(errorCode in setOf("AUTH_REQUIRED","NETWORK","CONFLICT","REMOTE"))
        db.withTransaction {
            val rec=recording(recordingId);check(rec.policyCode!="demo_2of3")
            val state=if(errorCode=="AUTH_REQUIRED") "NEEDS_AUTH" else "FAILED"
            dao.update(rec.copy(syncState=state));dao.failure(rec.id,state,errorCode)
        }
    }
    internal suspend fun reconcile() = withContext(Dispatchers.IO) {
        for (recording in dao.recordings()) {
            val id = UUID.fromString(recording.id)
            val dir = directory(id)
            dir.listFiles { f -> f.extension == "tmp" }?.forEach { it.delete() }
            val wasActive = recording.captureState in setOf("STARTING","RECORDING","STOPPING")
            val canReconcile = wasActive || recording.captureState == "FAILED"
            if (wasActive) capture(id,CaptureState.INTERRUPTED)
            try {
                withKey(id) { key ->
                    var previous = ByteArray(32)
                    val indexed = segments(id).associateBy { it.segmentIndex }
                    val finals = dir.listFiles { f -> f.extension == "swseg" }!!.sortedBy { it.nameWithoutExtension.toLongOrNull() ?: Long.MAX_VALUE }
                    var total = 0L
                    for ((i,f) in finals.withIndex()) {
                        require(f.length() <= Segments.MAX_OBJECT_BYTES)
                        val bytes = f.readBytes()
                        val h = Segments.parse(bytes)
                        require(f.name == "$i.swseg" && h.sampleRate == recording.sampleRate)
                        Segments.decryptVerified(key,bytes,id,i.toLong(),previous).fill(0)
                        val existing = indexed[i.toLong()]
                        if (existing != null) require(existing.ciphertextSha256 == Segments.hex(Segments.hash(bytes)))
                        else { check(canReconcile) { "SEALED_ORPHAN" }; db.withTransaction {
                            dao.segment(row(f,bytes))
                            if(recording.policyCode!="demo_2of3") dao.outbox(LocalOutbox(recording.id,h.index,Segments.hex(Segments.hash(bytes))))
                        } }
                        previous = Segments.hash(bytes); total += h.sampleCount
                    }
                    require(indexed.keys.all { it < finals.size }) { "MISSING_FINAL" }
                    if (canReconcile) dao.update(recording.copy(captureState = if (wasActive) "INTERRUPTED" else recording.captureState,
                        segmentCount = finals.size,durationSamples = total))
                    else require(recording.segmentCount == finals.size && recording.durationSamples == total)
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                dao.integrity(recording.id,"FAILED") // Preserve all final objects, including damaged ones.
            }
        }
    }
}
