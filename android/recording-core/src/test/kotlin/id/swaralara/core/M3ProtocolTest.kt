package id.swaralara.core

import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.TinkJsonProtoKeysetFormat
import id.swaralara.crypto.BoundShare
import id.swaralara.crypto.SegmentSession
import id.swaralara.crypto.Segments
import id.swaralara.crypto.ThresholdShares
import java.io.File
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.AEADBadTagException
import org.junit.Assert.*
import org.junit.Test

/** Real Tink/JCA on the JVM. Does not simulate Room, Android Keystore or device isolation. */
class M3ProtocolTest {
    private class Peer {
        val id = UUID.randomUUID()
        val user = UUID.randomUUID()
        val hpke: KeysetHandle = Hpke.fresh()
        val public = Hpke.publicBytes(hpke)
        val signing =
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
        val spki = encodeBase64(signing.public.encoded)

        fun sign(bytes: ByteArray) =
            encodeBase64(
                Signature.getInstance("SHA256withECDSA")
                    .apply {
                        initSign(signing.private)
                        update(bytes)
                    }
                    .sign()
            )
    }

    private data class Setup(
        val id: UUID,
        val peers: List<Peer>,
        val packet: SignedPolicyPackage,
        val binding: PolicyBinding,
    )

    private fun setup(code: String = "recovery_2of3"): Setup {
        val peers = List(if (code == "recovery_2of3") 3 else 2) { Peer() }
        val id = UUID.randomUUID()
        val members =
            peers.mapIndexed { i, p ->
                CloudMember(
                    i + 1,
                    p.user,
                    p.id,
                    M3Wire.hash(p.public),
                    M3Wire.hash(p.signing.public.encoded),
                )
            }
        val policy = CloudCapturePolicy(peers[0].user, peers[0].id, code, members)
        val raw = policy.bytes(id)
        val packet = SignedPolicyPackage(encodeBase64(raw), peers[0].sign(raw))
        return Setup(id, peers, packet, M3Wire.policy(packet))
    }

    private fun request(
        s: Setup,
        key: KeysetHandle = Hpke.fresh(),
    ): Pair<KeyAccessRequest, KeysetHandle> {
        val issued = System.currentTimeMillis()
        val draft =
            KeyAccessRequest(
                UUID.randomUUID(),
                s.id,
                s.peers[0].id,
                s.packet,
                encodeBase64(Hpke.publicBytes(key)),
                issued,
                issued + M3Wire.MAX_LIFETIME,
                UUID.randomUUID(),
                "",
            )
        return draft.copy(signatureBase64 = s.peers[0].sign(M3Wire.requestBytes(draft))) to key
    }

    private fun shares(s: Setup, key: ByteArray) =
        ThresholdShares.split(
            s.id,
            s.binding.hash,
            M3Wire.threshold(s.binding.policy),
            s.peers.map { it.id },
            key,
        )

    private fun release(s: Setup, r: KeyAccessRequest, share: BoundShare): ShareRelease {
        val peer = s.peers[share.index - 1]
        val at = System.currentTimeMillis()
        val nonce = UUID.randomUUID()
        val context = M3Wire.releaseContext(r, share.index, peer.id, at, nonce)
        val raw = ThresholdShares.encode(share)
        val ciphertext =
            try {
                Hpke.seal(decodeBase64(r.publicKeysetBase64), raw, context)
            } finally {
                raw.fill(0)
            }
        return ShareRelease(
            r.requestId,
            s.id,
            share.index,
            peer.id,
            at,
            nonce,
            encodeBase64(ciphertext),
            encodeBase64(context),
            M3Wire.hash(ciphertext),
            peer.sign(M3Wire.releaseSignature(context, ciphertext)),
        )
    }

    @Test
    fun bothPoliciesEnvelopeReleaseEveryAllowedPairAndRealGcmRoundTrip() {
        for (code in listOf("owner_required_2of2", "recovery_2of3")) {
            val s = setup(code)
            val key = ByteArray(32).also(SecureRandom()::nextBytes)
            val parts = shares(s, key)
            val pcm = ByteArray(128) { it.toByte() }
            val audio = SegmentSession(s.id, key.copyOf(), 16000).use { it.encrypt(pcm) }
            try {
                val received =
                    parts.mapIndexed { i, share ->
                        val context =
                            M3Wire.envelopeContext(s.binding, share.index, share.holderDeviceId)
                        val raw = ThresholdShares.encode(share)
                        val encrypted =
                            try {
                                Hpke.seal(s.peers[i].public, raw, context)
                            } finally {
                                raw.fill(0)
                            }
                        val signature =
                            s.peers[0].sign(M3Wire.envelopeSignature(context, encrypted))
                        M3Wire.verify(
                            s.peers[0].spki,
                            M3Wire.envelopeSignature(context, encrypted),
                            signature,
                        )
                        val opened = Hpke.open(s.peers[i].hpke, encrypted, context)
                        try {
                            ThresholdShares.decode(opened)
                        } finally {
                            opened.fill(0)
                        }
                    }
                try {
                    for (a in received.indices) for (b in a + 1 until received.size) {
                        val (r, privateKey) = request(s)
                        M3Wire.verify(s.peers[0].spki, M3Wire.requestBytes(r), r.signatureBase64)
                        val released =
                            listOf(release(s, r, received[a]), release(s, r, received[b]))
                        val opened =
                            released.map { e ->
                                val context = decodeBase64(e.contextBase64)
                                val bytes = decodeBase64(e.ciphertextBase64)
                                M3Wire.verify(
                                    s.peers[e.shareIndex - 1].spki,
                                    M3Wire.releaseSignature(context, bytes),
                                    e.holderSignatureBase64,
                                )
                                val raw = Hpke.open(privateKey, bytes, context)
                                try {
                                    ThresholdShares.decode(raw)
                                } finally {
                                    raw.fill(0)
                                }
                            }
                        try {
                            val restored =
                                ThresholdShares.recover(
                                    s.id,
                                    s.binding.hash,
                                    M3Wire.threshold(s.binding.policy),
                                    opened,
                                )
                            try {
                                assertArrayEquals(key, restored)
                                val plaintext =
                                    Segments.decryptVerified(
                                        restored,
                                        audio,
                                        s.id,
                                        0,
                                        ByteArray(32),
                                    )
                                try {
                                    assertArrayEquals(pcm, plaintext)
                                } finally {
                                    plaintext.fill(0)
                                }
                            } finally {
                                restored.fill(0)
                            }
                        } finally {
                            opened.forEach { it.close() }
                        }
                    }
                } finally {
                    received.forEach { it.close() }
                }
            } finally {
                parts.forEach { it.close() }
                key.fill(0)
                pcm.fill(0)
            }
        }
    }

    @Test
    fun wrongRecipientAndEveryRequestContextBindingRejectReplay() {
        val s = setup()
        val secret = ByteArray(32).also(SecureRandom()::nextBytes)
        val parts = shares(s, secret)
        try {
            val (r, privateKey) = request(s)
            val e = release(s, r, parts[1])
            val ciphertext = decodeBase64(e.ciphertextBase64)
            assertThrows(Exception::class.java) {
                Hpke.open(Hpke.fresh(), ciphertext, decodeBase64(e.contextBase64))
            }
            for (changed in
                listOf(
                    r.copy(requestId = UUID.randomUUID()),
                    r.copy(recordingId = UUID.randomUUID()),
                    r.copy(requesterDeviceId = s.peers[2].id),
                    r.copy(expiresAt = r.expiresAt + 1),
                    r.copy(nonce = UUID.randomUUID()),
                    r.copy(publicKeysetBase64 = encodeBase64(Hpke.publicBytes(Hpke.fresh()))),
                )) {
                val context =
                    M3Wire.releaseContext(
                        changed,
                        e.shareIndex,
                        e.holderDeviceId,
                        e.issuedAt,
                        e.nonce,
                    )
                assertThrows(Exception::class.java) { Hpke.open(privateKey, ciphertext, context) }
            }
            assertThrows(Exception::class.java) {
                Hpke.open(
                    privateKey,
                    ciphertext,
                    M3Wire.releaseContext(r, 1, e.holderDeviceId, e.issuedAt, e.nonce),
                )
            }
            assertThrows(Exception::class.java) {
                Hpke.open(
                    privateKey,
                    ciphertext,
                    M3Wire.releaseContext(r, 2, s.peers[2].id, e.issuedAt, e.nonce),
                )
            }
            assertThrows(Exception::class.java) {
                Hpke.open(
                    privateKey,
                    ciphertext,
                    M3Wire.releaseContext(r, 2, e.holderDeviceId, e.issuedAt, UUID.randomUUID()),
                )
            }
        } finally {
            parts.forEach { it.close() }
            secret.fill(0)
        }
    }

    @Test
    fun hpkeConfidentialityDoesNotReplacePinnedSenderAuthentication() {
        val recipient = Peer()
        val owner = Peer()
        val attacker = Peer()
        val context = M3Wire.fields("swaralara/test/v1", M3Wire.uuid(recipient.id))
        val plaintext = ByteArray(104)
        val ciphertext = Hpke.seal(recipient.public, plaintext, context)
        val opened = Hpke.open(recipient.hpke, ciphertext, context)
        assertArrayEquals(plaintext, opened)
        opened.fill(0)
        val bytes = M3Wire.envelopeSignature(context, ciphertext)
        val signature = owner.sign(bytes)
        M3Wire.verify(owner.spki, bytes, signature)
        assertThrows(Exception::class.java) {
            M3Wire.verify(owner.spki, bytes, attacker.sign(bytes))
        }
        val altered = bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { M3Wire.verify(owner.spki, altered, signature) }
        val changed =
            context.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(Exception::class.java) { Hpke.open(recipient.hpke, ciphertext, changed) }
    }

    @Test
    fun strictPolicyActionBase64AndExpiryParsingRejectMalformedInputs() {
        val s = setup()
        val at = System.currentTimeMillis()
        val action =
            ActionBinding(
                "share_ack",
                s.id,
                s.id,
                s.peers[1].id,
                s.binding.hash,
                "a".repeat(64),
                at,
                at + M3Wire.MAX_LIFETIME,
                UUID.randomUUID(),
            )
        val bytes = M3Wire.action(action)
        assertEquals(action, M3Wire.action(bytes))
        assertThrows(Exception::class.java) { M3Wire.action(bytes + byteArrayOf(0)) }
        assertThrows(Exception::class.java) { M3Wire.action(bytes.copyOf().also { it[0] = 0x7f }) }
        assertThrows(Exception::class.java) { M3Wire.decodeBounded("AA==\n", 4) }
        assertThrows(Exception::class.java) { M3Wire.decodeBounded("AAAA", 1) }
        M3Wire.live(at, at + M3Wire.MAX_LIFETIME, at)
        assertThrows(Exception::class.java) { M3Wire.live(at, at + M3Wire.MAX_LIFETIME + 1, at) }
        assertThrows(Exception::class.java) { M3Wire.live(at, at + 100, at + 100) }
        val malformed = decodeBase64(s.packet.snapshotBase64) + byteArrayOf(0)
        assertThrows(Exception::class.java) {
            M3Wire.policy(s.packet.copy(snapshotBase64 = encodeBase64(malformed)))
        }
    }

    @Test
    fun signedButIncorrectShareStillFailsAudioAuthentication() {
        val s = setup("owner_required_2of2")
        val secret = ByteArray(32).also(SecureRandom()::nextBytes)
        val parts = shares(s, secret)
        val audio = SegmentSession(s.id, secret.copyOf(), 16000).use { it.encrypt(ByteArray(128)) }
        try {
            val (r, privateKey) = request(s)
            val valid = release(s, r, parts[1])
            val context = decodeBase64(valid.contextBase64)
            val raw =
                ThresholdShares.encode(parts[1]).also {
                    it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
                }
            val encrypted =
                try {
                    Hpke.seal(decodeBase64(r.publicKeysetBase64), raw, context)
                } finally {
                    raw.fill(0)
                }
            val signature = s.peers[1].sign(M3Wire.releaseSignature(context, encrypted))
            M3Wire.verify(s.peers[1].spki, M3Wire.releaseSignature(context, encrypted), signature)
            val opened = Hpke.open(privateKey, encrypted, context)
            val bad =
                try {
                    ThresholdShares.decode(opened)
                } finally {
                    opened.fill(0)
                }
            try {
                val recovered =
                    ThresholdShares.recover(
                        s.id,
                        s.binding.hash,
                        M3Wire.threshold(s.binding.policy),
                        listOf(parts[0], bad),
                    )
                try {
                    assertThrows(AEADBadTagException::class.java) {
                        Segments.decryptVerified(recovered, audio, s.id, 0, ByteArray(32))
                    }
                } finally {
                    recovered.fill(0)
                }
            } finally {
                bad.close()
            }
        } finally {
            parts.forEach { it.close() }
            secret.fill(0)
        }
    }

    @Test
    fun publicKeyParserRejectsPrivateKeysetsAndFreshRequestsHaveDistinctKeys() {
        val handle = Hpke.fresh()
        val privateJson =
            TinkJsonProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())
                .toByteArray()
        try {
            assertThrows(Exception::class.java) { Hpke.publicHandle(privateJson) }
        } finally {
            privateJson.fill(0)
        }
        val s = setup("owner_required_2of2")
        val (first, _) = request(s)
        val (second, _) = request(s)
        assertNotEquals(first.publicKeysetBase64, second.publicKeysetBase64)
        assertNotEquals(first.requestId, second.requestId)
    }

    @Test
    fun exportPublicJvmVectorsForRealDerWebCryptoInterop() {
        val s = setup("owner_required_2of2")
        val owner = s.peers[0]
        val holder = s.peers[1]
        val context = M3Wire.envelopeContext(s.binding, 2, holder.id)
        val at = System.currentTimeMillis()
        val signatureBytes =
            M3Wire.envelopeSignature(context, ByteArray(157).also(SecureRandom()::nextBytes))
        val (r, _) = request(s)
        val releaseContext = M3Wire.releaseContext(r, 2, holder.id, at, UUID.randomUUID())
        val releaseBytes =
            M3Wire.releaseSignature(releaseContext, ByteArray(157).also(SecureRandom()::nextBytes))
        val ack =
            M3Wire.action(
                ActionBinding(
                    "share_ack",
                    s.id,
                    s.id,
                    holder.id,
                    s.binding.hash,
                    "a".repeat(64),
                    at,
                    at + M3Wire.MAX_LIFETIME,
                    UUID.randomUUID(),
                )
            )
        val cancel =
            M3Wire.action(
                ActionBinding(
                    "request_cancel",
                    s.id,
                    r.requestId,
                    owner.id,
                    s.binding.hash,
                    M3Wire.hash(M3Wire.requestBytes(r)),
                    at,
                    r.expiresAt,
                    UUID.randomUUID(),
                )
            )
        fun vector(name: String, peer: Peer, bytes: ByteArray) =
            """{"name":"$name","spkiBase64":"${peer.spki}","payloadBase64":"${encodeBase64(bytes)}","signatureBase64":"${peer.sign(bytes)}"}"""
        val vectors =
            listOf(
                vector("policy", owner, decodeBase64(s.packet.snapshotBase64)),
                vector("envelope", owner, signatureBytes),
                vector("ack", holder, ack),
                vector("request", owner, M3Wire.requestBytes(r)),
                vector("release", holder, releaseBytes),
                vector("cancel", owner, cancel),
            )
        File("build/m3-jvm-public-signatures.json").apply {
            parentFile.mkdirs()
            writeText(
                """{"schema":"swl-m3-public-signatures-v1","synthetic":true,"origin":"jvm","vectors":[${vectors.joinToString(",")}] }"""
            )
        }
    }
}
