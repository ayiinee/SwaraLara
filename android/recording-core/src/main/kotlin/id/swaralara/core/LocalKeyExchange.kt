package id.swaralara.core

import androidx.room.withTransaction
import id.swaralara.crypto.BoundShare
import id.swaralara.crypto.Segments
import id.swaralara.crypto.ThresholdShares
import java.nio.ByteBuffer
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

internal class LocalKeyExchange(
    private val db: LocalDatabase,
    private val vault: LocalVault,
    private val identity: DeviceIdentity,
    private val now: () -> Long = System::currentTimeMillis,
) : SecureKeyExchange {
    private val dao = db.dao()
    private val controls = Mutex()

    private suspend fun <T> operation(block: suspend () -> T): T =
        withContext(Dispatchers.IO) { controls.withLock { block() } }

    private fun fingerprint(base64: String, max: Int) =
        M3Wire.hash(M3Wire.decodeBounded(base64, max))

    override suspend fun pinTrustedDevice(
        userId: UUID,
        device: PublicDeviceIdentity,
        expectedHpkeFingerprint: String,
        expectedSigningFingerprint: String,
    ) = operation { pinLocked(userId, device, expectedHpkeFingerprint, expectedSigningFingerprint) }

    private suspend fun pinLocked(
        userId: UUID,
        device: PublicDeviceIdentity,
        expectedHpkeFingerprint: String,
        expectedSigningFingerprint: String,
    ) {
        require(
            device.hpkeFingerprint == expectedHpkeFingerprint &&
                device.signingFingerprint == expectedSigningFingerprint
        ) {
            "FINGERPRINT_NOT_CONFIRMED"
        }
        val hpke = M3Wire.decodeBounded(device.hpkePublicKeysetBase64, 4096)
        val spki = M3Wire.decodeBounded(device.signingPublicSpkiBase64, 200)
        require(
            M3Wire.hash(hpke) == expectedHpkeFingerprint &&
                M3Wire.hash(spki) == expectedSigningFingerprint
        ) {
            "FINGERPRINT_CHANGED"
        }
        Hpke.publicHandle(hpke)
        val proof =
            ByteBuffer.allocate(84)
                .put("SWD2".toByteArray(Charsets.US_ASCII))
                .apply { putUuid(device.deviceId) }
                .put(Segments.hash(hpke))
                .put(Segments.hash(spki))
                .array()
        M3Wire.verify(device.signingPublicSpkiBase64, proof, device.proofSignatureBase64)
        val row =
            LocalTrustedDevice(
                device.deviceId.toString(),
                userId.toString(),
                device.hpkePublicKeysetBase64,
                device.signingPublicSpkiBase64,
                expectedHpkeFingerprint,
                expectedSigningFingerprint,
            )
        db.withTransaction {
            val old = dao.trusted(row.deviceId)
            if (old == null) dao.trusted(row) else require(old == row) { "TRUSTED_DEVICE_CHANGED" }
        }
    }

    override suspend fun acceptPolicyDevices(
        policy: SignedPolicyPackage,
        devices: List<PublicDeviceIdentity>,
    ) = operation {
        val p = this.policy(policy)
        ownMember(p)
        require(
            devices.map { it.deviceId }.toSet() == p.policy.members.map { it.deviceId }.toSet() &&
                devices.size == p.policy.members.size
        )
        db.withTransaction {
            p.policy.members.forEach { member ->
                val device = devices.single { it.deviceId == member.deviceId }
                pinLocked(member.userId, device, member.hpkeFingerprint, member.signingFingerprint)
            }
        }
    }

    override suspend fun pendingRequests() = operation {
        dao.expireRequests(now())
        dao.closedRequests().forEach { KeyProtector.destroyRequestKey(UUID.fromString(it)) }
        dao.pendingRequests().map { M3Json.request(it.packetJson) }
    }

    override suspend fun outgoingCancellations() = operation {
        val own = identity.publicIdentity().deviceId
        dao.cancellations().mapNotNull { row ->
            val action = M3Json.action(row.packetJson)
            val binding = M3Wire.action(M3Wire.decodeBounded(action.payloadBase64, 1024))
            if (binding.deviceId == own && binding.expiresAt > now())
                UUID.fromString(row.requestId) to action
            else null
        }
    }

    private suspend fun trusted(member: CloudMember): LocalTrustedDevice {
        val own = identity.publicIdentity()
        if (member.deviceId == own.deviceId && dao.trusted(own.deviceId.toString()) == null) {
            require(
                member.hpkeFingerprint == own.hpkeFingerprint &&
                    member.signingFingerprint == own.signingFingerprint
            ) {
                "OWN_DEVICE_CHANGED"
            }
            dao.trusted(
                LocalTrustedDevice(
                    own.deviceId.toString(),
                    member.userId.toString(),
                    own.hpkePublicKeysetBase64,
                    own.signingPublicSpkiBase64,
                    own.hpkeFingerprint,
                    own.signingFingerprint,
                )
            )
        }
        val d =
            requireNotNull(dao.trusted(member.deviceId.toString())) { "TRUSTED_KEY_UNAVAILABLE" }
        require(
            d.userId == member.userId.toString() &&
                d.hpkeFingerprint == member.hpkeFingerprint &&
                d.signingFingerprint == member.signingFingerprint
        ) {
            "TRUSTED_DEVICE_CHANGED"
        }
        require(
            fingerprint(d.hpkePublicBase64, 4096) == member.hpkeFingerprint &&
                fingerprint(d.signingSpkiBase64, 200) == member.signingFingerprint
        )
        return d
    }

    private suspend fun policy(packet: SignedPolicyPackage): PolicyBinding {
        val p = M3Wire.policy(packet)
        val owner = trusted(p.policy.members.first())
        M3Wire.verify(
            owner.signingSpkiBase64,
            M3Wire.decodeBounded(packet.snapshotBase64, 512),
            packet.signatureBase64,
        )
        return p
    }

    private suspend fun ownMember(p: PolicyBinding): CloudMember {
        val own = identity.publicIdentity()
        val member = p.policy.members.single { it.deviceId == own.deviceId }
        trusted(member)
        require(
            member.hpkeFingerprint == own.hpkeFingerprint &&
                member.signingFingerprint == own.signingFingerprint
        ) {
            "OWN_DEVICE_CHANGED"
        }
        return member
    }

    private suspend fun exportPolicyLocked(id: UUID): SignedPolicyPackage {
        val row = requireNotNull(dao.cloud(id.toString())) { "DEMO_CLOUD_FORBIDDEN" }
        return SignedPolicyPackage(row.snapshotBase64, row.signatureBase64)
    }

    override suspend fun exportPolicy(recordingId: UUID) = operation {
        exportPolicyLocked(recordingId)
    }

    private suspend fun verifyEnvelope(p: PolicyBinding, e: ShareEnvelope): ByteArray {
        require(e.schemeVersion == "shamir-bc-gf256-v1") { "SHARE_SCHEME" }
        require(
            e.recordingId == p.id &&
                e.policyHash == p.hash &&
                e.shareIndex in 1..p.policy.members.size
        ) {
            "ENVELOPE_BINDING"
        }
        require(p.policy.members[e.shareIndex - 1].deviceId == e.holderDeviceId) {
            "HOLDER_BINDING"
        }
        val context = M3Wire.envelopeContext(p, e.shareIndex, e.holderDeviceId)
        require(context.contentEquals(M3Wire.decodeBounded(e.contextBase64, 4096))) {
            "ENVELOPE_CONTEXT"
        }
        val ciphertext = M3Wire.decodeBounded(e.ciphertextBase64, 8192)
        require(M3Wire.hash(ciphertext) == e.ciphertextHash) { "ENVELOPE_HASH" }
        M3Wire.verify(
            trusted(p.policy.members.first()).signingSpkiBase64,
            M3Wire.envelopeSignature(context, ciphertext),
            e.ownerSignatureBase64,
        )
        return ciphertext
    }

    private fun shareBinding(p: PolicyBinding, e: ShareEnvelope, share: BoundShare) {
        require(
            share.recordingId == p.id &&
                share.policyHash == p.hash &&
                share.policy == M3Wire.threshold(p.policy) &&
                share.index == e.shareIndex &&
                share.holderDeviceId == e.holderDeviceId
        ) {
            "SHARE_BINDING"
        }
    }

    private suspend fun updateRecovery(id: UUID) {
        val rec = dao.recording(id.toString()) ?: return
        val count = M3Wire.policy(exportPolicyLocked(id)).policy.members.size
        val envelopes = dao.shares(id.toString(), "OUTBOUND")
        val state =
            when {
                envelopes.size != count -> "DEGRADED"
                envelopes.all { it.acknowledgmentJson != null } -> "HOLDERS_ACKNOWLEDGED"
                envelopes.all { it.uploadedAt != null } -> "ENVELOPES_UPLOADED"
                else -> "ENVELOPES_QUEUED"
            }
        dao.update(rec.copy(recoveryState = state))
    }

    override suspend fun prepareDistribution(recordingId: UUID): List<ShareEnvelope> = operation {
        val packet = exportPolicyLocked(recordingId)
        val p = policy(packet)
        require(p.id == recordingId && ownMember(p).shareIndex == 1) { "OWNER_REQUIRED" }
        try {
            val devices = p.policy.members.map { trusted(it) }
            val old = dao.shares(recordingId.toString(), "OUTBOUND")
            if (old.isNotEmpty()) {
                require(old.size == p.policy.members.size) { "DISTRIBUTION_INCOMPLETE" }
                val cached =
                    old.map { M3Json.envelope(it.packetJson).also { e -> verifyEnvelope(p, e) } }
                acceptAckLocked(recordingId, receiveShareLocked(packet, cached.first()))
                return@operation cached
            }
            val rec = vault.recording(recordingId)
            require(rec.captureState in setOf("SEALED", "INTERRUPTED")) { "CAPTURE_ACTIVE" }
            check(vault.inspect(recordingId).passed) { "INVALID_RECORDING" }
            val envelopes =
                vault.withKey(recordingId) { key ->
                    val shares =
                        ThresholdShares.split(
                            recordingId,
                            p.hash,
                            M3Wire.threshold(p.policy),
                            p.policy.members.map { it.deviceId },
                            key,
                        )
                    try {
                        shares.mapIndexed { index, share ->
                            val context =
                                M3Wire.envelopeContext(p, share.index, share.holderDeviceId)
                            val raw = ThresholdShares.encode(share)
                            val encrypted =
                                try {
                                    Hpke.seal(
                                        M3Wire.decodeBounded(devices[index].hpkePublicBase64, 4096),
                                        raw,
                                        context,
                                    )
                                } finally {
                                    raw.fill(0)
                                }
                            ShareEnvelope(
                                recordingId,
                                p.hash,
                                share.index,
                                share.holderDeviceId,
                                encodeBase64(encrypted),
                                encodeBase64(context),
                                M3Wire.hash(encrypted),
                                encodeBase64(
                                    identity.sign(M3Wire.envelopeSignature(context, encrypted))
                                ),
                            )
                        }
                    } finally {
                        shares.forEach { it.close() }
                    }
                }
            db.withTransaction {
                envelopes.forEach {
                    dao.share(
                        LocalShareEnvelope(
                            recordingId.toString(),
                            it.shareIndex,
                            "OUTBOUND",
                            M3Json.envelope(it),
                            M3Json.policy(packet).toString(),
                        )
                    )
                }
            }
            // Owner retains only its own HPKE share in addition to the temporary wrapped full DEK.
            val ack = receiveShareLocked(packet, envelopes.first())
            acceptAckLocked(recordingId, ack)
            updateRecovery(recordingId)
            envelopes
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            dao.recording(recordingId.toString())?.let {
                dao.update(it.copy(recoveryState = "DEGRADED"))
            }
            throw e
        }
    }

    private fun signedAction(a: ActionBinding): DeviceSignedAction {
        val bytes = M3Wire.action(a)
        return DeviceSignedAction(encodeBase64(bytes), encodeBase64(identity.sign(bytes)))
    }

    private suspend fun receiveShareLocked(
        packet: SignedPolicyPackage,
        envelope: ShareEnvelope,
    ): DeviceSignedAction {
        val p = policy(packet)
        val own = ownMember(p)
        require(envelope.holderDeviceId == own.deviceId && envelope.shareIndex == own.shareIndex) {
            "WRONG_HOLDER"
        }
        val ciphertext = verifyEnvelope(p, envelope)
        val raw =
            identity.openEnvelope(ciphertext, M3Wire.decodeBounded(envelope.contextBase64, 4096))
        try {
            ThresholdShares.decode(raw).use { shareBinding(p, envelope, it) }
        } finally {
            raw.fill(0)
        }
        val old =
            dao.shares(p.id.toString(), "INBOUND").singleOrNull { it.shareIndex == own.shareIndex }
        if (old != null)
            require(M3Json.envelope(old.packetJson).ciphertextHash == envelope.ciphertextHash) {
                "IMMUTABLE_ENVELOPE"
            }
        val timestamp = now()
        val ack =
            old?.acknowledgmentJson?.let(M3Json::action)?.takeIf {
                val a = M3Wire.action(M3Wire.decodeBounded(it.payloadBase64, 1024))
                now() < a.expiresAt
            }
                ?: signedAction(
                    ActionBinding(
                        "share_ack",
                        p.id,
                        p.id,
                        own.deviceId,
                        p.hash,
                        envelope.ciphertextHash,
                        timestamp,
                        timestamp + M3Wire.MAX_LIFETIME,
                        UUID.randomUUID(),
                    )
                )
        db.withTransaction {
            if (old == null)
                dao.share(
                    LocalShareEnvelope(
                        p.id.toString(),
                        own.shareIndex,
                        "INBOUND",
                        M3Json.envelope(envelope),
                        M3Json.policy(packet).toString(),
                        acknowledgmentJson = M3Json.action(ack),
                    )
                )
            else dao.shareAck(p.id.toString(), own.shareIndex, "INBOUND", M3Json.action(ack))
        }
        return ack
    }

    override suspend fun receiveShare(policy: SignedPolicyPackage, envelope: ShareEnvelope) =
        operation {
            receiveShareLocked(policy, envelope)
        }

    override suspend fun authorizeShareRead(policy: SignedPolicyPackage) = operation {
        val p = this.policy(policy)
        val own = ownMember(p)
        val timestamp = now()
        signedAction(
            ActionBinding(
                "my_share",
                p.id,
                p.id,
                own.deviceId,
                p.hash,
                p.hash,
                timestamp,
                timestamp + M3Wire.MAX_LIFETIME,
                UUID.randomUUID(),
            )
        )
    }

    override suspend fun acknowledgeEnvelopeUpload(receipt: EnvelopeUploadReceipt) = operation {
        val row =
            dao.shares(receipt.recordingId.toString(), "OUTBOUND").single {
                it.shareIndex == receipt.shareIndex
            }
        require(
            M3Json.envelope(row.packetJson).ciphertextHash == receipt.ciphertextHash &&
                receipt.receivedAtServer > 0 &&
                receipt.receivedAtServer <= now() + 30_000
        ) {
            "ENVELOPE_RECEIPT_BINDING"
        }
        db.withTransaction {
            if (row.uploadedAt == null)
                dao.shareUploaded(
                    receipt.recordingId.toString(),
                    receipt.shareIndex,
                    receipt.receivedAtServer,
                )
            updateRecovery(receipt.recordingId)
        }
    }

    private suspend fun verifyAck(
        p: PolicyBinding,
        e: ShareEnvelope,
        ack: DeviceSignedAction,
        fresh: Boolean,
    ) {
        val bytes = M3Wire.decodeBounded(ack.payloadBase64, 1024)
        val a = M3Wire.action(bytes)
        require(
            a.action == "share_ack" &&
                a.recordingId == p.id &&
                a.resourceId == p.id &&
                a.deviceId == e.holderDeviceId &&
                a.policyHash == p.hash &&
                a.objectHash == e.ciphertextHash
        ) {
            "ACK_BINDING"
        }
        if (fresh) M3Wire.live(a.issuedAt, a.expiresAt, now())
        M3Wire.verify(
            trusted(p.policy.members[e.shareIndex - 1]).signingSpkiBase64,
            bytes,
            ack.signatureBase64,
        )
    }

    private suspend fun acceptAckLocked(id: UUID, ack: DeviceSignedAction) {
        val p = policy(exportPolicyLocked(id))
        require(ownMember(p).shareIndex == 1) { "OWNER_REQUIRED" }
        val a = M3Wire.action(M3Wire.decodeBounded(ack.payloadBase64, 1024))
        val row =
            dao.shares(id.toString(), "OUTBOUND").single {
                M3Json.envelope(it.packetJson).holderDeviceId == a.deviceId
            }
        verifyAck(p, M3Json.envelope(row.packetJson), ack, true)
        db.withTransaction {
            dao.shareAck(id.toString(), row.shareIndex, "OUTBOUND", M3Json.action(ack))
            updateRecovery(id)
        }
    }

    override suspend fun acceptAcknowledgment(
        recordingId: UUID,
        acknowledgment: DeviceSignedAction,
    ) = operation { acceptAckLocked(recordingId, acknowledgment) }

    override suspend fun retireLocalKey(recordingId: UUID, thresholdOnlyConsent: Boolean) =
        operation {
            require(thresholdOnlyConsent) { "THRESHOLD_CONSENT_REQUIRED" }
            val p = policy(exportPolicyLocked(recordingId))
            require(ownMember(p).shareIndex == 1) { "OWNER_REQUIRED" }
            if (dao.retirement(recordingId.toString()) != null) {
                KeyProtector.destroyRecordingKey(recordingId)
                return@operation
            }
            check(vault.inspect(recordingId).passed) { "INVALID_RECORDING" }
            vault.withKeyLifecycle(recordingId) {
                db.withTransaction {
                    val rec = vault.recording(recordingId)
                    require(dao.key(rec.id)?.envelopeKind == "local_dek_v2") {
                        "LEGACY_KEY_RETIREMENT_UNAVAILABLE"
                    }
                    require(
                        rec.syncState == "SYNCED" &&
                            rec.captureState in setOf("SEALED", "INTERRUPTED")
                    ) {
                        "SYNC_REQUIRED"
                    }
                    val envelopes = dao.shares(rec.id, "OUTBOUND")
                    require(
                        envelopes.size == p.policy.members.size &&
                            envelopes.all { it.uploadedAt != null && it.acknowledgmentJson != null }
                    ) {
                        "ALL_HOLDERS_REQUIRED"
                    }
                    for (row in envelopes) {
                        val envelope = M3Json.envelope(row.packetJson)
                        verifyEnvelope(p, envelope)
                        verifyAck(
                            p,
                            envelope,
                            M3Json.action(requireNotNull(row.acknowledgmentJson)),
                            false,
                        )
                    }
                    val own = dao.shares(rec.id, "INBOUND").single { it.shareIndex == 1 }
                    require(
                        M3Json.envelope(own.packetJson).ciphertextHash ==
                            M3Json.envelope(envelopes.first().packetJson).ciphertextHash
                    ) {
                        "OWNER_SHARE_REQUIRED"
                    }
                    val ownEnvelope = M3Json.envelope(own.packetJson)
                    val ownCiphertext = verifyEnvelope(p, ownEnvelope)
                    val raw =
                        identity.openEnvelope(
                            ownCiphertext,
                            M3Wire.decodeBounded(ownEnvelope.contextBase64, 4096),
                        )
                    try {
                        ThresholdShares.decode(raw).use { shareBinding(p, ownEnvelope, it) }
                    } finally {
                        raw.fill(0)
                    }
                    vault.recoveredKeys.clearRecording(recordingId)
                    dao.retirement(LocalKeyRetirement(rec.id, p.hash, now()))
                    dao.deleteKey(rec.id)
                    dao.update(
                        rec.copy(
                            recoveryState = "HOLDERS_ACKNOWLEDGED",
                            integrityState = "KEY_REQUIRED",
                        )
                    )
                }
                // The v2 KEK is unique to this recording. Removing its alias also invalidates old
                // SQLite/WAL copies.
                // Reconciliation and retries repeat this deletion after a crash between DB commit
                // and Keystore.
                KeyProtector.destroyRecordingKey(recordingId)
            }
        }

    private suspend fun validateRequest(r: KeyAccessRequest): PolicyBinding {
        val p = policy(r.policy)
        require(p.id == r.recordingId) { "REQUEST_BINDING" }
        val requester = p.policy.members.single { it.deviceId == r.requesterDeviceId }
        M3Wire.live(r.issuedAt, r.expiresAt, now())
        require(dao.cancellation(r.requestId.toString()) == null) { "REQUEST_CANCELLED" }
        Hpke.publicHandle(M3Wire.decodeBounded(r.publicKeysetBase64, 4096))
        M3Wire.verify(
            trusted(requester).signingSpkiBase64,
            M3Wire.requestBytes(r),
            r.signatureBase64,
        )
        return p
    }

    override suspend fun createRequest(
        policy: SignedPolicyPackage,
        lifetimeMillis: Long,
    ): KeyAccessRequest = operation {
        require(lifetimeMillis in 1..M3Wire.MAX_LIFETIME)
        val p = this.policy(policy)
        val own = ownMember(p)
        val id = UUID.randomUUID()
        val handle = Hpke.fresh()
        val timestamp = now()
        val draft =
            KeyAccessRequest(
                id,
                p.id,
                own.deviceId,
                policy,
                encodeBase64(Hpke.publicBytes(handle)),
                timestamp,
                timestamp + lifetimeMillis,
                UUID.randomUUID(),
                "",
            )
        val request =
            draft.copy(signatureBase64 = encodeBase64(identity.sign(M3Wire.requestBytes(draft))))
        val raw = Hpke.privateBytes(handle)
        try {
            dao.request(
                LocalM3Request(
                    id.toString(),
                    p.id.toString(),
                    M3Json.request(request),
                    KeyProtector.forRequest(id).wrap("request-hpke/$id/${p.hash}", raw),
                    request.expiresAt,
                )
            )
        } finally {
            raw.fill(0)
        }
        request
    }

    override suspend fun approveAndRelease(
        request: KeyAccessRequest,
        userApproved: Boolean,
    ): ShareRelease = operation {
        require(userApproved) { "APPROVAL_REQUIRED" }
        val p = validateRequest(request)
        val own = ownMember(p)
        val old = dao.release(request.requestId.toString(), own.shareIndex)
        if (old != null) {
            val cached = M3Json.release(old.packetJson)
            require(
                M3Wire.releaseContext(
                        request,
                        own.shareIndex,
                        own.deviceId,
                        cached.issuedAt,
                        cached.nonce,
                    )
                    .contentEquals(M3Wire.decodeBounded(cached.contextBase64, 4096))
            ) {
                "REQUEST_CONFLICT"
            }
            return@operation cached
        }
        val stored =
            dao.shares(p.id.toString(), "INBOUND").single { it.shareIndex == own.shareIndex }
        val envelope = M3Json.envelope(stored.packetJson)
        val ciphertext = verifyEnvelope(p, envelope)
        val raw =
            identity.openEnvelope(ciphertext, M3Wire.decodeBounded(envelope.contextBase64, 4096))
        val release =
            try {
                ThresholdShares.decode(raw).use { shareBinding(p, envelope, it) }
                val issuedAt = now()
                val nonce = UUID.randomUUID()
                val context =
                    M3Wire.releaseContext(request, own.shareIndex, own.deviceId, issuedAt, nonce)
                val sealed =
                    Hpke.seal(M3Wire.decodeBounded(request.publicKeysetBase64, 4096), raw, context)
                ShareRelease(
                    request.requestId,
                    p.id,
                    own.shareIndex,
                    own.deviceId,
                    issuedAt,
                    nonce,
                    encodeBase64(sealed),
                    encodeBase64(context),
                    M3Wire.hash(sealed),
                    encodeBase64(identity.sign(M3Wire.releaseSignature(context, sealed))),
                )
            } finally {
                raw.fill(0)
            }
        dao.release(
            LocalM3Release(request.requestId.toString(), own.shareIndex, M3Json.release(release))
        )
        release
    }

    override suspend fun authorizeReleasesRead(requestId: UUID) = operation {
        val row = requireNotNull(dao.request(requestId.toString())) { "REQUEST_UNAVAILABLE" }
        require(row.state in setOf("PENDING", "OPEN")) { "REQUEST_CLOSED" }
        val r = M3Json.request(row.packetJson)
        val p = validateRequest(r)
        val own = ownMember(p)
        require(own.deviceId == r.requesterDeviceId) { "REQUESTER_REQUIRED" }
        signedAction(
            ActionBinding(
                "release_list",
                p.id,
                r.requestId,
                own.deviceId,
                p.hash,
                M3Wire.hash(M3Wire.requestBytes(r)),
                now(),
                r.expiresAt,
                UUID.randomUUID(),
            )
        )
    }

    override suspend fun recover(requestId: UUID, releases: List<ShareRelease>): KeyRecoveryResult =
        operation {
            val row = requireNotNull(dao.request(requestId.toString())) { "REQUEST_UNAVAILABLE" }
            vault.recoveredKeys.clearRequest(requestId)
            if (row.expiresAt <= now()) {
                dao.closeRequest(row.requestId, "EXPIRED")
                KeyProtector.destroyRequestKey(requestId)
                return@operation KeyRecoveryResult(
                    false,
                    "REQUEST_EXPIRED",
                    "Permintaan kedaluwarsa; buat permintaan baru.",
                )
            }
            require(row.state in setOf("PENDING", "OPEN")) { "REQUEST_CLOSED" }
            val decoded = mutableListOf<BoundShare>()
            try {
                val request = M3Json.request(row.packetJson)
                val p = validateRequest(request)
                require(ownMember(p).deviceId == request.requesterDeviceId) { "REQUESTER_REQUIRED" }
                require(
                    releases.size in 2..p.policy.members.size &&
                        releases.map { it.shareIndex }.distinct().size == releases.size
                ) {
                    "THRESHOLD_REQUIRED"
                }
                val rawKeyset =
                    KeyProtector.forRequest(requestId)
                        .unwrap("request-hpke/$requestId/${p.hash}", row.wrappedPrivateKey)
                try {
                    val privateKey = Hpke.privateHandle(rawKeyset)
                    for (release in releases) {
                        require(
                            release.requestId == requestId &&
                                release.recordingId == p.id &&
                                release.shareIndex in 1..p.policy.members.size
                        ) {
                            "RELEASE_BINDING"
                        }
                        val member = p.policy.members[release.shareIndex - 1]
                        require(
                            member.deviceId == release.holderDeviceId &&
                                release.issuedAt >= request.issuedAt - 30_000 &&
                                release.issuedAt <= now() + 30_000
                        ) {
                            "RELEASE_HOLDER"
                        }
                        val context =
                            M3Wire.releaseContext(
                                request,
                                release.shareIndex,
                                release.holderDeviceId,
                                release.issuedAt,
                                release.nonce,
                            )
                        require(
                            context.contentEquals(M3Wire.decodeBounded(release.contextBase64, 4096))
                        ) {
                            "RELEASE_CONTEXT"
                        }
                        val ciphertext = M3Wire.decodeBounded(release.ciphertextBase64, 8192)
                        require(M3Wire.hash(ciphertext) == release.ciphertextHash) {
                            "RELEASE_HASH"
                        }
                        M3Wire.verify(
                            trusted(member).signingSpkiBase64,
                            M3Wire.releaseSignature(context, ciphertext),
                            release.holderSignatureBase64,
                        )
                        val raw = Hpke.open(privateKey, ciphertext, context)
                        try {
                            val share = ThresholdShares.decode(raw)
                            try {
                                require(
                                    share.recordingId == p.id &&
                                        share.policyHash == p.hash &&
                                        share.policy == M3Wire.threshold(p.policy) &&
                                        share.index == release.shareIndex &&
                                        share.holderDeviceId == member.deviceId
                                ) {
                                    "SHARE_BINDING"
                                }
                                decoded.add(share)
                            } catch (e: Exception) {
                                share.close()
                                throw e
                            }
                        } finally {
                            raw.fill(0)
                        }
                    }
                } finally {
                    rawKeyset.fill(0)
                }
                val key = ThresholdShares.recover(p.id, p.hash, M3Wire.threshold(p.policy), decoded)
                try {
                    // Always authenticate with the reconstructed DEK, never fall back to the local
                    // full key.
                    vault.verifyWithKey(p.id, key)
                    vault.recoveredKeys.hold(p.id, requestId, key, request.expiresAt)
                    dao.requestState(row.requestId, "OPEN")
                } finally {
                    key.fill(0)
                }
                KeyRecoveryResult(
                    true,
                    "VERIFIED_PARTIAL",
                    "Kunci dipulihkan dan segmen lokal lolos autentikasi. Final manifest belum tersedia.",
                )
            } catch (e: Exception) {
                vault.recoveredKeys.clearRequest(requestId)
                if (e is CancellationException) throw e
                KeyRecoveryResult(
                    false,
                    "RECOVERY_FAILED",
                    "Pemulihan belum berhasil: periksa bagian, binding, masa berlaku, dan paket. Hasil ini tidak membuktikan audio asli diubah.",
                )
            } finally {
                decoded.forEach { it.close() }
            }
        }

    override suspend fun cancelRequest(requestId: UUID): DeviceSignedAction = operation {
        val row = requireNotNull(dao.request(requestId.toString())) { "REQUEST_UNAVAILABLE" }
        dao.cancellation(row.requestId)?.let {
            return@operation M3Json.action(it.packetJson)
        }
        val r = M3Json.request(row.packetJson)
        val p = validateRequest(r)
        require(
            ownMember(p).deviceId == r.requesterDeviceId && row.state in setOf("PENDING", "OPEN")
        ) {
            "REQUESTER_REQUIRED"
        }
        val action =
            signedAction(
                ActionBinding(
                    "request_cancel",
                    p.id,
                    r.requestId,
                    r.requesterDeviceId,
                    p.hash,
                    M3Wire.hash(M3Wire.requestBytes(r)),
                    now(),
                    r.expiresAt,
                    UUID.randomUUID(),
                )
            )
        db.withTransaction {
            dao.cancellation(LocalM3Cancellation(row.requestId, M3Json.action(action)))
            dao.closeRequest(row.requestId, "CANCELLED")
        }
        vault.recoveredKeys.clearRequest(requestId)
        KeyProtector.destroyRequestKey(requestId)
        action
    }

    override suspend fun receiveCancellation(
        request: KeyAccessRequest,
        cancellation: DeviceSignedAction,
    ) = operation {
        val p = policy(request.policy)
        val bytes = M3Wire.decodeBounded(cancellation.payloadBase64, 1024)
        val a = M3Wire.action(bytes)
        require(request.recordingId == p.id)
        ownMember(p)
        M3Wire.verify(
            trusted(p.policy.members.single { it.deviceId == request.requesterDeviceId })
                .signingSpkiBase64,
            M3Wire.requestBytes(request),
            request.signatureBase64,
        )
        dao.request(request.requestId.toString())?.let {
            require(
                M3Wire.requestBytes(M3Json.request(it.packetJson))
                    .contentEquals(M3Wire.requestBytes(request))
            ) {
                "REQUEST_CONFLICT"
            }
        }
        require(
            a.action == "request_cancel" &&
                a.recordingId == p.id &&
                a.resourceId == request.requestId &&
                a.policyHash == p.hash &&
                a.objectHash == M3Wire.hash(M3Wire.requestBytes(request)) &&
                a.deviceId in setOf(request.requesterDeviceId, p.policy.sourceDeviceId)
        ) {
            "CANCELLATION_BINDING"
        }
        M3Wire.live(a.issuedAt, a.expiresAt, now())
        M3Wire.verify(
            trusted(p.policy.members.single { it.deviceId == a.deviceId }).signingSpkiBase64,
            bytes,
            cancellation.signatureBase64,
        )
        db.withTransaction {
            dao.cancellation(
                LocalM3Cancellation(request.requestId.toString(), M3Json.action(cancellation))
            )
            dao.request(request.requestId.toString())?.let {
                dao.closeRequest(it.requestId, "CANCELLED")
            }
        }
        vault.recoveredKeys.clearRequest(request.requestId)
        if (dao.request(request.requestId.toString()) != null)
            KeyProtector.destroyRequestKey(request.requestId)
    }

    override suspend fun closeRecovery(requestId: UUID) = operation {
        val row = requireNotNull(dao.request(requestId.toString())) { "REQUEST_UNAVAILABLE" }
        vault.recoveredKeys.clearRequest(requestId)
        dao.closeRequest(row.requestId, "CLOSED")
        KeyProtector.destroyRequestKey(requestId)
        Unit
    }

    override suspend fun closeOpenSessions() = operation { vault.closeRecoveredSessions() }
}
