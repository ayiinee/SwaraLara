package id.swaralara.core

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.ByteBuffer
import java.time.Instant
import java.util.UUID
import org.json.JSONObject

/**
 * HTTP DTOs preserve the original signed LP bytes. No private key or plaintext share crosses this
 * API.
 */
object M3TransportCodec {
    fun canonical(text: String) = text.filterNot(Char::isWhitespace)

    private fun value(o: JSONObject, name: String) = canonical(o.getString(name))

    fun policy(o: JSONObject) =
        SignedPolicyPackage(value(o, "policySnapshotBase64"), value(o, "policySignatureBase64"))

    fun recordingId(p: SignedPolicyPackage) = M3Wire.policy(p).id

    fun members(p: SignedPolicyPackage) = M3Wire.policy(p).policy.members

    fun capturePolicy(p: SignedPolicyPackage) = M3Wire.policy(p).policy

    fun publicDevice(o: JSONObject) =
        PublicDeviceIdentity(
            UUID.fromString(o.getString("deviceId")),
            value(o, "hpkePublicKeysetBase64"),
            o.getString("hpkeFingerprint"),
            value(o, "signingPublicSpkiBase64"),
            o.getString("signingFingerprint"),
            value(o, "proofSignatureBase64"),
        )

    fun envelope(e: ShareEnvelope) =
        JSONObject()
            .put("shareIndex", e.shareIndex)
            .put("holderDeviceId", e.holderDeviceId)
            .put("schemeVersion", e.schemeVersion)
            .put("envelopeCiphertextBase64", e.ciphertextBase64)
            .put("contextBytesBase64", e.contextBase64)
            .put("ownerSignatureBase64", e.ownerSignatureBase64)
            .put("ciphertextSha256", e.ciphertextHash)

    fun envelope(o: JSONObject): ShareEnvelope {
        val p = M3Wire.policy(policy(o))
        return ShareEnvelope(
            p.id,
            p.hash,
            o.getInt("shareIndex"),
            UUID.fromString(o.getString("holderDeviceId")),
            value(o, "envelopeCiphertextBase64"),
            value(o, "contextBytesBase64"),
            o.getString("ciphertextSha256"),
            value(o, "ownerSignatureBase64"),
            o.getString("schemeVersion"),
        )
    }

    fun request(r: KeyAccessRequest) =
        JSONObject()
            .put("id", r.requestId)
            .put("recordingId", r.recordingId)
            .put("requesterDeviceId", r.requesterDeviceId)
            .put("requestHpkePublicKeysetBase64", r.publicKeysetBase64)
            .put("requestBytesBase64", encodeBase64(M3Wire.requestBytes(r)))
            .put("requestSignatureBase64", r.signatureBase64)
            .put("expiresAt", Instant.ofEpochMilli(r.expiresAt).toString())

    private fun fields(raw: ByteArray, domain: String, sizes: List<Int>): List<ByteArray> {
        require(raw.size <= 4096)
        val input = DataInputStream(ByteArrayInputStream(raw))
        fun field(size: Int): ByteArray {
            val n = input.readInt()
            require(n == size && n <= input.available()) { "TRANSPORT_FIELD" }
            return ByteArray(n).also(input::readFully)
        }
        require(String(field(domain.length), Charsets.US_ASCII) == domain) { "TRANSPORT_DOMAIN" }
        val result = sizes.map(::field)
        require(input.available() == 0) { "TRANSPORT_TRAILING" }
        return result
    }

    private fun id(b: ByteArray) = ByteBuffer.wrap(b).let { UUID(it.long, it.long) }

    private fun time(b: ByteArray) = ByteBuffer.wrap(b).long

    fun request(o: JSONObject): KeyAccessRequest {
        val raw = M3Wire.decodeBounded(value(o, "requestBytesBase64"), 2048)
        val f = fields(raw, "swaralara/key-request/v1", listOf(16, 16, 16, 32, 32, 8, 8, 16))
        val r =
            KeyAccessRequest(
                id(f[0]),
                id(f[1]),
                id(f[2]),
                policy(o),
                value(o, "requestHpkePublicKeysetBase64"),
                time(f[5]),
                time(f[6]),
                id(f[7]),
                value(o, "requestSignatureBase64"),
            )
        require(
            r.requestId.toString() == o.getString("id") &&
                r.recordingId.toString() == o.getString("recordingId") &&
                r.requesterDeviceId.toString() == o.getString("requesterDeviceId") &&
                r.expiresAt == Instant.parse(o.getString("expiresAt")).toEpochMilli() &&
                raw.contentEquals(M3Wire.requestBytes(r))
        ) {
            "REQUEST_BINDING"
        }
        return r
    }

    fun release(o: JSONObject, request: KeyAccessRequest): ShareRelease {
        val context = value(o, "contextBytesBase64")
        val f =
            fields(
                M3Wire.decodeBounded(context, 4096),
                "swaralara/share-release/v1",
                listOf(16, 16, 16, 32, 32, 4, 16, 8, 8, 16),
            )
        val index = ByteBuffer.wrap(f[5]).int
        require(
            id(f[0]) == request.requestId &&
                id(f[1]) == request.recordingId &&
                index == o.getInt("shareIndex") &&
                id(f[6]).toString() == o.getString("holderDeviceId")
        ) {
            "RELEASE_BINDING"
        }
        return ShareRelease(
            id(f[0]),
            id(f[1]),
            index,
            id(f[6]),
            time(f[8]),
            id(f[9]),
            value(o, "releaseCiphertextBase64"),
            context,
            o.getString("ciphertextSha256"),
            value(o, "holderSignatureBase64"),
        )
    }

    fun action(a: DeviceSignedAction): JSONObject {
        val binding = M3Wire.action(M3Wire.decodeBounded(a.payloadBase64, 1024))
        return JSONObject()
            .put("deviceId", binding.deviceId)
            .put("actionBytesBase64", a.payloadBase64)
            .put("signatureBase64", a.signatureBase64)
    }

    fun actionDevice(a: DeviceSignedAction) =
        M3Wire.action(M3Wire.decodeBounded(a.payloadBase64, 1024)).deviceId

    fun actionExpiresAt(a: DeviceSignedAction) =
        M3Wire.action(M3Wire.decodeBounded(a.payloadBase64, 1024)).expiresAt
}
