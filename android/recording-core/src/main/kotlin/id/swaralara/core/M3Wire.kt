package id.swaralara.core

import id.swaralara.crypto.Segments
import id.swaralara.crypto.ThresholdPolicy
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.UUID

internal data class PolicyBinding(val id: UUID, val policy: CloudCapturePolicy, val hash: String)

internal data class ActionBinding(
    val action: String,
    val recordingId: UUID,
    val resourceId: UUID,
    val deviceId: UUID,
    val policyHash: String,
    val objectHash: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val nonce: UUID,
)

/** Every field, including the ASCII domain, is prefixed with a big-endian uint32 length. */
internal object M3Wire {
    const val MAX_LIFETIME = 900_000L

    fun hash(bytes: ByteArray) = Segments.hex(Segments.hash(bytes))

    fun uuid(id: UUID) = ByteBuffer.allocate(16).apply { putUuid(id) }.array()

    private fun long(value: Long) = ByteBuffer.allocate(8).putLong(value).array()

    private fun int(value: Int) = ByteBuffer.allocate(4).putInt(value).array()

    fun fields(domain: String, vararg parts: ByteArray): ByteArray =
        ByteArrayOutputStream().use { stream ->
            DataOutputStream(stream).use { out ->
                for (part in listOf(domain.toByteArray(Charsets.US_ASCII)) + parts.toList()) {
                    require(part.size <= 8192)
                    out.writeInt(part.size)
                    out.write(part)
                }
            }
            stream.toByteArray()
        }

    fun policy(packet: SignedPolicyPackage): PolicyBinding {
        val raw = decodeBounded(packet.snapshotBase64, 512)
        require(raw.size in setOf(248, 345)) { "POLICY_LENGTH" }
        val b = ByteBuffer.wrap(raw)
        require(b.int == 0x53575031) { "POLICY_VERSION" }
        val id = UUID(b.long, b.long)
        val owner = UUID(b.long, b.long)
        val source = UUID(b.long, b.long)
        val code = b.get().toInt()
        val count = b.get().toInt()
        require(code in 1..2 && count == (if (code == 1) 2 else 3) && raw.size == 54 + 97 * count)
        val members =
            (1..count).map {
                val x = b.get().toInt()
                val user = UUID(b.long, b.long)
                val device = UUID(b.long, b.long)
                CloudMember(
                    x,
                    user,
                    device,
                    Segments.hex(ByteArray(32).also(b::get)),
                    Segments.hex(ByteArray(32).also(b::get)),
                )
            }
        return PolicyBinding(
            id,
            CloudCapturePolicy(
                owner,
                source,
                if (code == 1) "owner_required_2of2" else "recovery_2of3",
                members,
            ),
            hash(raw),
        )
    }

    fun threshold(policy: CloudCapturePolicy) =
        if (policy.policyCode == "owner_required_2of2") ThresholdPolicy.OWNER_REQUIRED_2OF2
        else ThresholdPolicy.RECOVERY_2OF3

    fun envelopeContext(p: PolicyBinding, index: Int, holder: UUID) =
        fields(
            "swaralara/share-envelope/v1",
            uuid(p.id),
            hexBytes(p.hash),
            int(index),
            uuid(holder),
        )

    fun envelopeSignature(context: ByteArray, ciphertext: ByteArray) =
        fields("swaralara/share-envelope-signature/v1", context, Segments.hash(ciphertext))

    fun requestBytes(r: KeyAccessRequest): ByteArray =
        fields(
            "swaralara/key-request/v1",
            uuid(r.requestId),
            uuid(r.recordingId),
            uuid(r.requesterDeviceId),
            hexBytes(policy(r.policy).hash),
            Segments.hash(decodeBounded(r.publicKeysetBase64, 4096)),
            long(r.issuedAt),
            long(r.expiresAt),
            uuid(r.nonce),
        )

    fun releaseContext(r: KeyAccessRequest, index: Int, holder: UUID, issuedAt: Long, nonce: UUID) =
        fields(
            "swaralara/share-release/v1",
            uuid(r.requestId),
            uuid(r.recordingId),
            uuid(r.requesterDeviceId),
            hexBytes(policy(r.policy).hash),
            Segments.hash(requestBytes(r)),
            int(index),
            uuid(holder),
            long(r.expiresAt),
            long(issuedAt),
            uuid(nonce),
        )

    fun releaseSignature(context: ByteArray, ciphertext: ByteArray) =
        fields("swaralara/share-release-signature/v1", context, Segments.hash(ciphertext))

    fun action(a: ActionBinding) =
        fields(
            "swaralara/device-action/v1",
            a.action.toByteArray(Charsets.US_ASCII),
            uuid(a.recordingId),
            uuid(a.resourceId),
            uuid(a.deviceId),
            hexBytes(a.policyHash),
            hexBytes(a.objectHash),
            long(a.issuedAt),
            long(a.expiresAt),
            uuid(a.nonce),
        )

    fun action(bytes: ByteArray): ActionBinding {
        require(bytes.size <= 1024)
        val input = DataInputStream(ByteArrayInputStream(bytes))
        fun field(size: Int? = null): ByteArray {
            val n = input.readInt()
            require(n in 0..256 && (size == null || n == size) && n <= input.available())
            return ByteArray(n).also(input::readFully)
        }
        fun id() = ByteBuffer.wrap(field(16)).let { UUID(it.long, it.long) }
        fun time() = ByteBuffer.wrap(field(8)).long
        require(String(field(), Charsets.US_ASCII) == "swaralara/device-action/v1")
        val action = String(field(), Charsets.US_ASCII)
        require(action in setOf("share_ack", "request_cancel", "my_share", "release_list"))
        val result =
            ActionBinding(
                action,
                id(),
                id(),
                id(),
                Segments.hex(field(32)),
                Segments.hex(field(32)),
                time(),
                time(),
                id(),
            )
        require(input.available() == 0)
        return result
    }

    fun decodeBounded(text: String, max: Int): ByteArray {
        require(text.length <= ((max + 2) / 3) * 4 && text.matches(Regex("[A-Za-z0-9+/]*={0,2}"))) {
            "BASE64_LENGTH"
        }
        val bytes = decodeBase64(text)
        require(bytes.size <= max && encodeBase64(bytes) == text) { "BASE64_CANONICAL" }
        return bytes
    }

    fun verify(spkiBase64: String, bytes: ByteArray, signatureBase64: String) {
        val key =
            KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(decodeBounded(spkiBase64, 200)))
                as java.security.interfaces.ECPublicKey
        val expected =
            java.security.AlgorithmParameters.getInstance("EC")
                .apply { init(java.security.spec.ECGenParameterSpec("secp256r1")) }
                .getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        require(
            key.params.order == expected.order &&
                key.params.generator == expected.generator &&
                key.params.curve == expected.curve
        ) {
            "SIGNING_CURVE"
        }
        require(
            Signature.getInstance("SHA256withECDSA")
                .apply {
                    initVerify(key)
                    update(bytes)
                }
                .verify(decodeBounded(signatureBase64, 80))
        ) {
            "SIGNATURE_INVALID"
        }
    }

    fun live(issuedAt: Long, expiresAt: Long, now: Long) {
        require(
            issuedAt > 0 &&
                expiresAt > issuedAt &&
                expiresAt - issuedAt <= MAX_LIFETIME &&
                issuedAt <= now + 30_000 &&
                now < expiresAt
        ) {
            "REQUEST_EXPIRED_OR_INVALID"
        }
    }
}
