package id.swaralara.core

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Logical devices have separate identities, namespaces, databases and roots on one test emulator.
 */
@RunWith(AndroidJUnit4::class)
class KeyExchangeTest {
    private val context
        get() = ApplicationProvider.getApplicationContext<Context>()

    private var clock = System.currentTimeMillis()
    private var advancingClock = false

    private fun time() = if (advancingClock) clock++ else clock

    private val nodes = mutableListOf<Node>()

    private inner class Node {
        val userId = UUID.randomUUID()
        val namespace = "m3-test-${UUID.randomUUID()}"
        val databaseName = "$namespace.db"
        val root =
            File(context.filesDir, namespace).also {
                check(it.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
            }
        val protector = KeyProtector()
        val identity = DeviceIdentity(context, protector, namespace)
        var db = openDatabase()
        var vault = LocalVault(root, db, protector, identity, RecoverySessions { clock })
        var exchange = LocalKeyExchange(db, vault, identity) { time() }

        fun openDatabase() =
            Room.databaseBuilder(context, LocalDatabase::class.java, databaseName)
                .addMigrations(MIGRATION_1_2, MIGRATION_2_3)
                .build()

        fun restart() {
            vault.recoveredKeys.clearAll()
            db.close()
            db = openDatabase()
            vault = LocalVault(root, db, protector, identity, RecoverySessions { clock })
            exchange = LocalKeyExchange(db, vault, identity) { time() }
        }
    }

    private data class Group(val nodes: List<Node>, val id: UUID, val policy: CloudCapturePolicy)

    private suspend fun group(code: String = "recovery_2of3", pin: Boolean = true): Group {
        val participants = List(if (code == "recovery_2of3") 3 else 2) { Node().also(nodes::add) }
        if (pin) pinAll(participants)
        val members =
            participants.mapIndexed { i, n ->
                val p = n.identity.publicIdentity()
                CloudMember(i + 1, n.userId, p.deviceId, p.hpkeFingerprint, p.signingFingerprint)
            }
        val policy =
            CloudCapturePolicy(participants.first().userId, members.first().deviceId, code, members)
        val id = UUID.randomUUID()
        val owner = participants.first()
        owner.vault.create(id, CaptureConfig(cloudPolicy = policy), 16000).use { session ->
            owner.vault.capture(id, CaptureState.RECORDING)
            owner.vault.persist(id, session.encrypt(ByteArray(64000) { (it % 47).toByte() }))
            owner.vault.persist(id, session.encrypt(ByteArray(222)))
        }
        owner.vault.capture(id, CaptureState.SEALED)
        return Group(participants, id, policy)
    }

    private suspend fun pinAll(participants: List<Node>) {
        for (receiver in participants) for (sender in participants) {
            val public = sender.identity.publicIdentity()
            receiver.exchange.pinTrustedDevice(
                sender.userId,
                public,
                public.hpkeFingerprint,
                public.signingFingerprint,
            )
        }
    }

    private suspend fun rejects(block: suspend () -> Unit) {
        try {
            block()
            fail("Unexpected acceptance")
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
        }
    }

    private suspend fun distribute(
        g: Group,
        uploads: Boolean = true,
        acknowledge: Boolean = true,
    ): List<ShareEnvelope> {
        val owner = g.nodes.first()
        val packet = owner.exchange.exportPolicy(g.id)
        val envelopes = owner.exchange.prepareDistribution(g.id)
        for ((index, holder) in g.nodes.withIndex()) {
            val ack = holder.exchange.receiveShare(packet, envelopes[index])
            if (acknowledge) owner.exchange.acceptAcknowledgment(g.id, ack)
            if (uploads)
                owner.exchange.acknowledgeEnvelopeUpload(
                    EnvelopeUploadReceipt(g.id, index + 1, envelopes[index].ciphertextHash, clock)
                )
        }
        return envelopes
    }

    /**
     * Synthetic transport receipts exercise the gate; they do not claim M3 backend upload exists.
     */
    private suspend fun syncAudio(g: Group) {
        val owner = g.nodes.first()
        val snapshot = owner.vault.exportEncryptedSnapshot(g.id)
        for (s in snapshot.segments) owner.vault.acknowledgeUpload(
            UploadReceipt(g.id, s.index, s.objectHash, clock)
        )
    }

    @After
    fun cleanup() = runBlocking {
        for (n in nodes) {
            runCatching { n.vault.closeRecoveredSessions() }
            n.db.dao().recordings().forEach {
                KeyProtector.destroyRecordingKey(UUID.fromString(it.id))
            }
            n.db.dao().requestIds().forEach { KeyProtector.destroyRequestKey(UUID.fromString(it)) }
            n.db.close()
            check(n.root.canonicalPath.startsWith(context.filesDir.canonicalPath + File.separator))
            n.root.deleteRecursively()
            context.deleteDatabase(n.databaseName)
            context.deleteSharedPreferences("swl-device-${n.namespace}")
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                deleteEntry("swaralara.signing.${n.namespace}")
            }
        }
    }

    @Test
    fun bothPoliciesRequireThresholdAfterRetirementAndAllPairsAuthenticate() = runBlocking {
        for (code in listOf("owner_required_2of2", "recovery_2of3")) {
            val g = group(code)
            val owner = g.nodes.first()
            val snapshot = owner.vault.exportEncryptedSnapshot(g.id)
            val ciphertext = snapshot.segments.map { it.file.readBytes() }
            val oldWrapped = owner.db.dao().key(g.id.toString())!!.wrappedPayload.copyOf()
            val envelope = distribute(g, uploads = false, acknowledge = false)
            assertEquals(envelope, owner.exchange.prepareDistribution(g.id))
            rejects { owner.exchange.retireLocalKey(g.id, true) }
            assertNotNull(owner.db.dao().key(g.id.toString()))
            for ((index, holder) in g.nodes.withIndex()) {
                val ack =
                    holder.exchange.receiveShare(owner.exchange.exportPolicy(g.id), envelope[index])
                owner.exchange.acceptAcknowledgment(g.id, ack)
                owner.exchange.acknowledgeEnvelopeUpload(
                    EnvelopeUploadReceipt(g.id, index + 1, envelope[index].ciphertextHash, clock)
                )
            }
            rejects { owner.exchange.retireLocalKey(g.id, true) } // Audio not synced yet.
            syncAudio(g)
            rejects { owner.exchange.retireLocalKey(g.id, false) }
            val ownStored = owner.db.dao().shares(g.id.toString(), "INBOUND").single()
            val original = M3Json.envelope(ownStored.packetJson)
            val corrupted =
                decodeBase64(original.ciphertextBase64).also {
                    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                }
            owner.db.openHelper.writableDatabase.execSQL(
                "UPDATE LocalShareEnvelope SET packetJson=? WHERE recordingId=? AND direction='INBOUND'",
                arrayOf(
                    M3Json.envelope(original.copy(ciphertextBase64 = encodeBase64(corrupted))),
                    g.id.toString(),
                ),
            )
            rejects { owner.exchange.retireLocalKey(g.id, true) }
            assertNotNull(owner.db.dao().key(g.id.toString()))
            owner.db.openHelper.writableDatabase.execSQL(
                "UPDATE LocalShareEnvelope SET packetJson=? WHERE recordingId=? AND direction='INBOUND'",
                arrayOf(ownStored.packetJson, g.id.toString()),
            )
            owner.exchange.retireLocalKey(g.id, true)
            assertNull(owner.db.dao().key(g.id.toString()))
            val keystore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            assertFalse(keystore.containsAlias("swaralara.recording-kek.v2.${g.id}"))
            rejects { KeyProtector.forRecording(g.id).unwrap(g.id.toString(), oldWrapped) }
            keystore.load(null)
            assertFalse(keystore.containsAlias("swaralara.recording-kek.v2.${g.id}"))
            assertFalse(owner.vault.inspect(g.id).passed)
            assertEquals("KEY_REQUIRED", owner.vault.recording(g.id).integrityState)
            for (a in g.nodes.indices) for (b in a + 1 until g.nodes.size) {
                val request = owner.exchange.createRequest(owner.exchange.exportPolicy(g.id))
                val releases =
                    listOf(
                        g.nodes[a].exchange.approveAndRelease(request, true),
                        g.nodes[b].exchange.approveAndRelease(request, true),
                    )
                assertFalse(
                    owner.exchange.recover(request.requestId, listOf(releases.first())).passed
                )
                assertFalse(
                    owner.exchange
                        .recover(request.requestId, listOf(releases.first(), releases.first()))
                        .passed
                )
                assertTrue(owner.exchange.recover(request.requestId, releases).passed)
                assertTrue(owner.vault.inspect(g.id).passed)
                owner.exchange.closeRecovery(request.requestId)
                assertFalse(owner.vault.inspect(g.id).passed)
            }
            snapshot.segments.forEachIndexed { i, s ->
                assertArrayEquals(ciphertext[i], s.file.readBytes())
            }
            assertEquals("HOLDERS_ACKNOWLEDGED", owner.vault.recording(g.id).recoveryState)
        }
    }

    @Test
    fun hpkeRecipientContextOwnerSignatureAndPlaintextBindingFailClosed() = runBlocking {
        val g = group()
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        val other = g.nodes[2]
        val packet = owner.exchange.exportPolicy(g.id)
        val p = M3Wire.policy(packet)
        val envelope = owner.exchange.prepareDistribution(g.id)[1]
        rejects { other.exchange.receiveShare(packet, envelope) }
        rejects {
            other.identity.openEnvelope(
                decodeBase64(envelope.ciphertextBase64),
                decodeBase64(envelope.contextBase64),
            )
        }
        val badContext =
            decodeBase64(envelope.contextBase64).also {
                it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
            }
        rejects {
            holder.identity.openEnvelope(decodeBase64(envelope.ciphertextBase64), badContext)
        }
        rejects {
            holder.exchange.receiveShare(
                packet,
                envelope.copy(contextBase64 = encodeBase64(badContext)),
            )
        }
        rejects {
            holder.exchange.receiveShare(
                packet,
                envelope.copy(
                    ownerSignatureBase64 =
                        encodeBase64(
                            other.identity.sign(
                                M3Wire.envelopeSignature(
                                    decodeBase64(envelope.contextBase64),
                                    decodeBase64(envelope.ciphertextBase64),
                                )
                            )
                        )
                ),
            )
        }
        rejects {
            holder.exchange.receiveShare(
                packet.copy(
                    signatureBase64 =
                        encodeBase64(other.identity.sign(decodeBase64(packet.snapshotBase64)))
                ),
                envelope,
            )
        }
        val raw =
            holder.identity.openEnvelope(
                decodeBase64(envelope.ciphertextBase64),
                decodeBase64(envelope.contextBase64),
            )
        raw[55] = 3 // Index in SWB1, while envelope still claims index 2.
        val forgedCipher =
            try {
                Hpke.seal(
                    decodeBase64(holder.identity.publicIdentity().hpkePublicKeysetBase64),
                    raw,
                    decodeBase64(envelope.contextBase64),
                )
            } finally {
                raw.fill(0)
            }
        val forged =
            envelope.copy(
                ciphertextBase64 = encodeBase64(forgedCipher),
                ciphertextHash = M3Wire.hash(forgedCipher),
                ownerSignatureBase64 =
                    encodeBase64(
                        owner.identity.sign(
                            M3Wire.envelopeSignature(
                                decodeBase64(envelope.contextBase64),
                                forgedCipher,
                            )
                        )
                    ),
            )
        rejects { holder.exchange.receiveShare(packet, forged) }
        assertTrue(holder.db.dao().shares(g.id.toString(), "INBOUND").isEmpty())
        val ack = holder.exchange.receiveShare(packet, envelope)
        assertEquals(ack, holder.exchange.receiveShare(packet, envelope))
        val parsed = M3Wire.action(decodeBase64(ack.payloadBase64))
        assertEquals(p.hash, parsed.policyHash)
        assertEquals(envelope.ciphertextHash, parsed.objectHash)
        rejects {
            owner.exchange.acceptAcknowledgment(
                g.id,
                ack.copy(
                    signatureBase64 =
                        encodeBase64(other.identity.sign(decodeBase64(ack.payloadBase64)))
                ),
            )
        }
        rejects {
            owner.exchange.acknowledgeEnvelopeUpload(
                EnvelopeUploadReceipt(g.id, 2, "0".repeat(64), clock)
            )
        }
        assertNotNull(owner.db.dao().key(g.id.toString()))
    }

    @Test
    fun requestsAndReleasesCannotCrossRecipientResourceOrCancellation() = runBlocking {
        val g = group()
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        distribute(g)
        val packet = owner.exchange.exportPolicy(g.id)
        val request = owner.exchange.createRequest(packet)
        rejects { holder.exchange.approveAndRelease(request, false) }
        rejects { holder.exchange.approveAndRelease(request.copy(nonce = UUID.randomUUID()), true) }
        rejects {
            holder.exchange.approveAndRelease(
                request.copy(requesterDeviceId = g.nodes[2].identity.publicIdentity().deviceId),
                true,
            )
        }
        rejects {
            holder.exchange.approveAndRelease(request.copy(expiresAt = request.expiresAt + 1), true)
        }
        val own = owner.exchange.approveAndRelease(request, true)
        val release = holder.exchange.approveAndRelease(request, true)
        assertEquals(release, holder.exchange.approveAndRelease(request, true))
        val next = owner.exchange.createRequest(packet)
        assertNotEquals(request.publicKeysetBase64, next.publicKeysetBase64)
        assertFalse(owner.exchange.recover(next.requestId, listOf(own, release)).passed)
        assertFalse(
            owner.exchange
                .recover(
                    request.requestId,
                    listOf(
                        own,
                        release.copy(holderDeviceId = g.nodes[2].identity.publicIdentity().deviceId),
                    ),
                )
                .passed
        )
        // A full local DEK still exists here; invalid recovery must never use it as a fallback.
        assertNotNull(owner.db.dao().key(g.id.toString()))
        assertFalse(
            owner.exchange
                .recover(
                    request.requestId,
                    listOf(own, release.copy(ciphertextHash = "0".repeat(64))),
                )
                .passed
        )
        val cancellation = owner.exchange.cancelRequest(request.requestId)
        assertFalse(
            KeyStore.getInstance("AndroidKeyStore")
                .apply { load(null) }
                .containsAlias("swaralara.request-kek.v1.${request.requestId}")
        )
        holder.exchange.receiveCancellation(request, cancellation)
        rejects { holder.exchange.approveAndRelease(request, true) }
        rejects { owner.exchange.recover(request.requestId, listOf(own, release)) }
        assertEquals(
            0,
            owner.db.dao().request(request.requestId.toString())!!.wrappedPrivateKey.size,
        )
        val action = owner.exchange.authorizeShareRead(packet)
        assertEquals("my_share", M3Wire.action(decodeBase64(action.payloadBase64)).action)
        assertEquals(
            "release_list",
            M3Wire.action(
                    decodeBase64(owner.exchange.authorizeReleasesRead(next.requestId).payloadBase64)
                )
                .action,
        )
        val outsider = Node().also(nodes::add)
        pinAll(listOf(outsider) + g.nodes)
        rejects { outsider.exchange.createRequest(packet) }
    }

    @Test
    fun maliciousButSignedShareFailsGcmWithoutBlamingOrChangingAudio() = runBlocking {
        val g = group()
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        val envelopes = distribute(g)
        syncAudio(g)
        owner.exchange.retireLocalKey(g.id, true)
        val request = owner.exchange.createRequest(owner.exchange.exportPolicy(g.id))
        val own = owner.exchange.approveAndRelease(request, true)
        val valid = holder.exchange.approveAndRelease(request, true)
        val raw =
            holder.identity.openEnvelope(
                decodeBase64(envelopes[1].ciphertextBase64),
                decodeBase64(envelopes[1].contextBase64),
            )
        raw[raw.lastIndex] = (raw.last().toInt() xor 1).toByte()
        val context = decodeBase64(valid.contextBase64)
        val ciphertext =
            try {
                Hpke.seal(decodeBase64(request.publicKeysetBase64), raw, context)
            } finally {
                raw.fill(0)
            }
        val malicious =
            valid.copy(
                ciphertextBase64 = encodeBase64(ciphertext),
                ciphertextHash = M3Wire.hash(ciphertext),
                holderSignatureBase64 =
                    encodeBase64(holder.identity.sign(M3Wire.releaseSignature(context, ciphertext))),
            )
        val before = owner.vault.segments(g.id).map { File(it.path).readBytes() }
        val result = owner.exchange.recover(request.requestId, listOf(own, malicious))
        assertFalse(result.passed)
        assertEquals("RECOVERY_FAILED", result.code)
        assertEquals("KEY_REQUIRED", owner.vault.recording(g.id).integrityState)
        assertNull(owner.vault.recoveredKeys.copy(g.id))
        owner.vault.segments(g.id).forEachIndexed { i, s ->
            assertArrayEquals(before[i], File(s.path).readBytes())
        }
        assertTrue(owner.exchange.recover(request.requestId, listOf(own, valid)).passed)
        owner.exchange.closeOpenSessions()
        assertFalse(owner.vault.inspect(g.id).passed)
        assertEquals("CLOSED", owner.db.dao().request(request.requestId.toString())!!.state)
    }

    @Test
    fun expiredRequestAndLostKeystoreIdentityCannotRecoverOrResurrectKeys() = runBlocking {
        val g = group("owner_required_2of2")
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        distribute(g)
        syncAudio(g)
        owner.exchange.retireLocalKey(g.id, true)
        val request = owner.exchange.createRequest(owner.exchange.exportPolicy(g.id), 1000)
        val releases =
            listOf(
                owner.exchange.approveAndRelease(request, true),
                holder.exchange.approveAndRelease(request, true),
            )
        assertTrue(owner.exchange.recover(request.requestId, releases).passed)
        clock += 1001
        assertNull(owner.vault.recoveredKeys.copy(g.id))
        assertFalse(owner.vault.inspect(g.id).passed)
        assertEquals("REQUEST_EXPIRED", owner.exchange.recover(request.requestId, releases).code)
        assertEquals(
            0,
            owner.db.dao().request(request.requestId.toString())!!.wrappedPrivateKey.size,
        )
        rejects { holder.exchange.approveAndRelease(request, true) }
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry("swaralara.signing.${holder.namespace}")
        }
        rejects { holder.identity.publicIdentity() }
    }

    @Test
    fun restartKeepsImmutableEnvelopesAndWrappedRequestButNotRecoveredDek() = runBlocking {
        val g = group()
        val owner = g.nodes[0]
        val envelopes = distribute(g)
        syncAudio(g)
        owner.exchange.retireLocalKey(g.id, true)
        val packet = owner.exchange.exportPolicy(g.id)
        val request = owner.exchange.createRequest(packet)
        val releases =
            listOf(
                g.nodes[1].exchange.approveAndRelease(request, true),
                g.nodes[2].exchange.approveAndRelease(request, true),
            )
        val fingerprint = owner.identity.publicIdentity().hpkeFingerprint
        owner.restart()
        owner.vault.reconcile()
        assertEquals("KEY_REQUIRED", owner.vault.recording(g.id).integrityState)
        assertEquals(fingerprint, owner.identity.publicIdentity().hpkeFingerprint)
        assertEquals(envelopes, owner.exchange.prepareDistribution(g.id))
        assertTrue(owner.exchange.recover(request.requestId, releases).passed)
        owner.restart()
        owner.vault.reconcile()
        assertFalse(owner.vault.inspect(g.id).passed)
        assertNull(owner.db.dao().key(g.id.toString()))
        owner.exchange.closeRecovery(request.requestId)
        assertEquals(
            0,
            owner.db.dao().request(request.requestId.toString())!!.wrappedPrivateKey.size,
        )
    }

    @Test
    fun missingAndChangedPinnedKeysKeepFullDekAndNeverRebind() = runBlocking {
        val g = group(pin = false)
        val owner = g.nodes[0]
        rejects { owner.exchange.prepareDistribution(g.id) }
        assertEquals("DEGRADED", owner.vault.recording(g.id).recoveryState)
        assertTrue(owner.vault.inspect(g.id).passed)
        assertNotNull(owner.db.dao().key(g.id.toString()))
        pinAll(g.nodes)
        val member = g.nodes[1].identity.publicIdentity()
        rejects {
            owner.exchange.pinTrustedDevice(
                g.nodes[1].userId,
                member,
                "0".repeat(64),
                member.signingFingerprint,
            )
        }
        rejects {
            owner.exchange.pinTrustedDevice(
                UUID.randomUUID(),
                member,
                member.hpkeFingerprint,
                member.signingFingerprint,
            )
        }
        assertEquals(3, owner.exchange.prepareDistribution(g.id).size)
    }

    @Test
    fun legacySharedKekEnvelopeIsRetainedUntilAnExplicitKeyMigrationExists() = runBlocking {
        val g = group("owner_required_2of2")
        val owner = g.nodes.first()
        val legacy = owner.vault.withKey(g.id) { owner.protector.wrap(g.id.toString(), it) }
        owner.db.openHelper.writableDatabase.execSQL(
            "UPDATE LocalKeyEnvelope SET wrappedPayload=?,envelopeKind='local_dek_v1' WHERE recordingId=?",
            arrayOf(legacy, g.id.toString()),
        )
        KeyProtector.destroyRecordingKey(g.id)
        distribute(g)
        syncAudio(g)
        rejects { owner.exchange.retireLocalKey(g.id, true) }
        assertNotNull(owner.db.dao().key(g.id.toString()))
        assertNull(owner.db.dao().retirement(g.id.toString()))
        assertTrue(owner.vault.inspect(g.id).passed)
    }

    @Test
    fun versionTwoMigrationPreservesCloudRegistrationOutboxAndWrappedKey() = runBlocking {
        val name = "m3-migration-${UUID.randomUUID()}.db"
        val path = context.getDatabasePath(name)
        path.parentFile!!.mkdirs()
        val schema =
            InstrumentationRegistry.getInstrumentation()
                .context
                .assets
                .open("id.swaralara.core.LocalDatabase/2.json")
                .bufferedReader()
                .use { JSONObject(it.readText()).getJSONObject("database") }
        val id = UUID.randomUUID().toString()
        SQLiteDatabase.openOrCreateDatabase(path, null).use { old ->
            val entities = schema.getJSONArray("entities")
            for (i in 0 until entities.length()) {
                val e = entities.getJSONObject(i)
                old.execSQL(
                    e.getString("createSql").replace("\${TABLE_NAME}", e.getString("tableName"))
                )
            }
            val setup = schema.getJSONArray("setupQueries")
            for (i in 0 until setup.length()) old.execSQL(setup.getString(i))
            old.execSQL(
                "INSERT INTO LocalRecording VALUES (?, 'retrospective', 10, 'SEALED', 'PARTIAL', 'DEGRADED', 'UNVERIFIED', 16000, 1, 2, 1, 'owner_required_2of2')",
                arrayOf(id),
            )
            old.execSQL(
                "INSERT INTO LocalKeyEnvelope VALUES (?, ?, 'local_dek_v1')",
                arrayOf(id, byteArrayOf(7, 8, 9)),
            )
            old.execSQL(
                "INSERT INTO LocalCloudRegistration VALUES (?, ?, 'public-policy', 'public-snapshot', 'public-signature', 'stable-registration')",
                arrayOf(id, UUID.randomUUID().toString()),
            )
            old.execSQL(
                "INSERT INTO LocalOutbox VALUES (?, 0, ?, 'COMMITTED', 2, NULL)",
                arrayOf(id, "a".repeat(64)),
            )
            old.version = 2
        }
        val upgraded =
            Room.databaseBuilder(context, LocalDatabase::class.java, name)
                .addMigrations(MIGRATION_2_3)
                .build()
        try {
            assertEquals("stable-registration", upgraded.dao().cloud(id)!!.registrationJson)
            assertArrayEquals(byteArrayOf(7, 8, 9), upgraded.dao().key(id)!!.wrappedPayload)
            assertEquals("PARTIAL", upgraded.dao().recording(id)!!.syncState)
            assertTrue(upgraded.dao().shares(id, "OUTBOUND").isEmpty())
            upgraded.openHelper.writableDatabase
                .query("SELECT state,attempt FROM LocalOutbox WHERE recordingId=?", arrayOf(id))
                .use {
                    assertTrue(it.moveToFirst())
                    assertEquals("COMMITTED", it.getString(0))
                    assertEquals(2, it.getInt(1))
                }
        } finally {
            upgraded.close()
            context.deleteDatabase(name)
        }
    }

    @Test
    fun androidDerPublicVectorsForBackendHandoff() = runBlocking {
        val g = group("owner_required_2of2")
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        val envelopes = distribute(g)
        val packet = owner.exchange.exportPolicy(g.id)
        val ack = holder.exchange.receiveShare(packet, envelopes[1])
        val request = owner.exchange.createRequest(packet)
        val release = holder.exchange.approveAndRelease(request, true)
        val cancel = owner.exchange.cancelRequest(request.requestId)
        val vectors = JSONArray()
        fun add(name: String, node: Node, bytes: ByteArray, signature: String) {
            vectors.put(
                JSONObject()
                    .put("name", name)
                    .put("spkiBase64", node.identity.publicIdentity().signingPublicSpkiBase64)
                    .put("payloadBase64", encodeBase64(bytes))
                    .put("signatureBase64", signature)
            )
        }
        add("policy", owner, decodeBase64(packet.snapshotBase64), packet.signatureBase64)
        add(
            "envelope",
            owner,
            M3Wire.envelopeSignature(
                decodeBase64(envelopes[1].contextBase64),
                decodeBase64(envelopes[1].ciphertextBase64),
            ),
            envelopes[1].ownerSignatureBase64,
        )
        add("ack", holder, decodeBase64(ack.payloadBase64), ack.signatureBase64)
        add("request", owner, M3Wire.requestBytes(request), request.signatureBase64)
        add(
            "release",
            holder,
            M3Wire.releaseSignature(
                decodeBase64(release.contextBase64),
                decodeBase64(release.ciphertextBase64),
            ),
            release.holderSignatureBase64,
        )
        add("cancel", owner, decodeBase64(cancel.payloadBase64), cancel.signatureBase64)
        File(context.filesDir, "m3-public-signatures.json")
            .writeText(
                JSONObject()
                    .put("schema", "swl-m3-public-signatures-v1")
                    .put("synthetic", true)
                    .put("origin", "android")
                    .put("vectors", vectors)
                    .toString(2)
            )
        assertEquals(6, vectors.length())
    }

    @Test
    fun maximumLifetimeCapturesOneTimestampEvenAcrossMillisecondTicks() = runBlocking {
        val g = group("owner_required_2of2")
        val owner = g.nodes[0]
        val holder = g.nodes[1]
        val envelope = owner.exchange.prepareDistribution(g.id)[1]
        advancingClock = true
        val packet = owner.exchange.exportPolicy(g.id)
        val ack = holder.exchange.receiveShare(packet, envelope)
        val action = M3Wire.action(decodeBase64(ack.payloadBase64))
        assertEquals(M3Wire.MAX_LIFETIME, action.expiresAt - action.issuedAt)
        val read =
            M3Wire.action(decodeBase64(owner.exchange.authorizeShareRead(packet).payloadBase64))
        assertEquals(M3Wire.MAX_LIFETIME, read.expiresAt - read.issuedAt)
        val request = owner.exchange.createRequest(packet)
        assertEquals(M3Wire.MAX_LIFETIME, request.expiresAt - request.issuedAt)
        assertEquals(2, holder.exchange.approveAndRelease(request, true).shareIndex)
    }
}
