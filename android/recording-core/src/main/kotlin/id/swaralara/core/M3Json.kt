package id.swaralara.core

import java.util.UUID
import org.json.JSONObject

/** Persistence of public metadata and ciphertext only; never used to sign reserialized JSON. */
internal object M3Json {
    fun policy(p: SignedPolicyPackage) =
        JSONObject()
            .put("snapshotBase64", p.snapshotBase64)
            .put("signatureBase64", p.signatureBase64)

    fun policy(p: JSONObject) =
        SignedPolicyPackage(p.getString("snapshotBase64"), p.getString("signatureBase64"))

    fun action(a: DeviceSignedAction) =
        JSONObject()
            .put("payloadBase64", a.payloadBase64)
            .put("signatureBase64", a.signatureBase64)
            .toString()

    fun action(s: String) =
        JSONObject(s).let {
            DeviceSignedAction(it.getString("payloadBase64"), it.getString("signatureBase64"))
        }

    fun envelope(e: ShareEnvelope) =
        JSONObject()
            .put("recordingId", e.recordingId)
            .put("policyHash", e.policyHash)
            .put("shareIndex", e.shareIndex)
            .put("holderDeviceId", e.holderDeviceId)
            .put("ciphertextBase64", e.ciphertextBase64)
            .put("contextBase64", e.contextBase64)
            .put("ciphertextHash", e.ciphertextHash)
            .put("ownerSignatureBase64", e.ownerSignatureBase64)
            .put("schemeVersion", e.schemeVersion)
            .toString()

    fun envelope(s: String) =
        JSONObject(s).let {
            ShareEnvelope(
                UUID.fromString(it.getString("recordingId")),
                it.getString("policyHash"),
                it.getInt("shareIndex"),
                UUID.fromString(it.getString("holderDeviceId")),
                it.getString("ciphertextBase64"),
                it.getString("contextBase64"),
                it.getString("ciphertextHash"),
                it.getString("ownerSignatureBase64"),
                it.getString("schemeVersion"),
            )
        }

    fun request(r: KeyAccessRequest) =
        JSONObject()
            .put("requestId", r.requestId)
            .put("recordingId", r.recordingId)
            .put("requesterDeviceId", r.requesterDeviceId)
            .put("policy", policy(r.policy))
            .put("publicKeysetBase64", r.publicKeysetBase64)
            .put("issuedAt", r.issuedAt)
            .put("expiresAt", r.expiresAt)
            .put("nonce", r.nonce)
            .put("signatureBase64", r.signatureBase64)
            .toString()

    fun request(s: String) =
        JSONObject(s).let {
            KeyAccessRequest(
                UUID.fromString(it.getString("requestId")),
                UUID.fromString(it.getString("recordingId")),
                UUID.fromString(it.getString("requesterDeviceId")),
                policy(it.getJSONObject("policy")),
                it.getString("publicKeysetBase64"),
                it.getLong("issuedAt"),
                it.getLong("expiresAt"),
                UUID.fromString(it.getString("nonce")),
                it.getString("signatureBase64"),
            )
        }

    fun release(r: ShareRelease) =
        JSONObject()
            .put("requestId", r.requestId)
            .put("recordingId", r.recordingId)
            .put("shareIndex", r.shareIndex)
            .put("holderDeviceId", r.holderDeviceId)
            .put("issuedAt", r.issuedAt)
            .put("nonce", r.nonce)
            .put("ciphertextBase64", r.ciphertextBase64)
            .put("contextBase64", r.contextBase64)
            .put("ciphertextHash", r.ciphertextHash)
            .put("holderSignatureBase64", r.holderSignatureBase64)
            .toString()

    fun release(s: String) =
        JSONObject(s).let {
            ShareRelease(
                UUID.fromString(it.getString("requestId")),
                UUID.fromString(it.getString("recordingId")),
                it.getInt("shareIndex"),
                UUID.fromString(it.getString("holderDeviceId")),
                it.getLong("issuedAt"),
                UUID.fromString(it.getString("nonce")),
                it.getString("ciphertextBase64"),
                it.getString("contextBase64"),
                it.getString("ciphertextHash"),
                it.getString("holderSignatureBase64"),
            )
        }
}
