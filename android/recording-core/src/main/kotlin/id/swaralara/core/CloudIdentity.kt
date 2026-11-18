package id.swaralara.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.JsonKeysetWriter
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig
import id.swaralara.crypto.Segments
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

data class CloudMember(
    val shareIndex: Int,
    val userId: UUID,
    val deviceId: UUID,
    val hpkeFingerprint: String,
    val signingFingerprint: String,
)

data class CloudCapturePolicy(
    val ownerUserId: UUID,
    val sourceDeviceId: UUID,
    val policyCode: String,
    val members: List<CloudMember>,
) {
    init {
        require(policyCode in setOf("owner_required_2of2", "recovery_2of3"))
        require(members.size == if (policyCode == "owner_required_2of2") 2 else 3)
        require(members.map { it.shareIndex } == (1..members.size).toList())
        require(members.map { it.userId }.distinct().size == members.size)
        require(members.map { it.deviceId }.distinct().size == members.size)
        require(members.first().userId == ownerUserId && members.first().deviceId == sourceDeviceId)
        require(
            members.all {
                it.hpkeFingerprint.matches(Regex("[0-9a-f]{64}")) &&
                    it.signingFingerprint.matches(Regex("[0-9a-f]{64}"))
            }
        )
    }

    internal fun bytes(id: UUID): ByteArray =
        ByteBuffer.allocate(54 + 97 * members.size)
            .apply {
                put("SWP1".toByteArray())
                putUuid(id)
                putUuid(ownerUserId)
                putUuid(sourceDeviceId)
                put(if (policyCode == "owner_required_2of2") 1.toByte() else 2.toByte())
                put(members.size.toByte())
                members.forEach {
                    put(it.shareIndex.toByte())
                    putUuid(it.userId)
                    putUuid(it.deviceId)
                    put(hexBytes(it.hpkeFingerprint))
                    put(hexBytes(it.signingFingerprint))
                }
            }
            .array()

    internal fun json() =
        JSONObject()
            .put("ownerUserId", ownerUserId)
            .put("sourceDeviceId", sourceDeviceId)
            .put("policyCode", policyCode)
            .put(
                "members",
                JSONArray(
                    members.map {
                        JSONObject()
                            .put("shareIndex", it.shareIndex)
                            .put("userId", it.userId)
                            .put("deviceId", it.deviceId)
                            .put("hpkeFingerprint", it.hpkeFingerprint)
                            .put("signingFingerprint", it.signingFingerprint)
                    }
                ),
            )
            .toString()

    companion object {
        internal fun fromJson(text: String): CloudCapturePolicy {
            val p = JSONObject(text)
            val a = p.getJSONArray("members")
            return CloudCapturePolicy(
                UUID.fromString(p.getString("ownerUserId")),
                UUID.fromString(p.getString("sourceDeviceId")),
                p.getString("policyCode"),
                (0 until a.length()).map {
                    val m = a.getJSONObject(it)
                    CloudMember(
                        m.getInt("shareIndex"),
                        UUID.fromString(m.getString("userId")),
                        UUID.fromString(m.getString("deviceId")),
                        m.getString("hpkeFingerprint"),
                        m.getString("signingFingerprint"),
                    )
                },
            )
        }
    }
}

internal fun ByteBuffer.putUuid(id: UUID) {
    putLong(id.mostSignificantBits)
    putLong(id.leastSignificantBits)
}

internal fun hexBytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun encodeBase64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

fun decodeBase64(text: String): ByteArray = java.util.Base64.getDecoder().decode(text)

data class PublicDeviceIdentity(
    val deviceId: UUID,
    val hpkePublicKeysetBase64: String,
    val hpkeFingerprint: String,
    val signingPublicSpkiBase64: String,
    val signingFingerprint: String,
    val proofSignatureBase64: String,
)

/**
 * Only public identity and signatures cross this facade; private HPKE bytes stay Keystore-wrapped.
 */
class DeviceIdentity
internal constructor(
    context: Context,
    private val protector: KeyProtector,
    internal val namespace: String = "v1",
) {
    init {
        require(namespace.matches(Regex("[a-z0-9-]{1,80}")))
    }

    private val prefs =
        context.applicationContext.getSharedPreferences(
            if (namespace == "v1") "swl-device-v1" else "swl-device-$namespace",
            Context.MODE_PRIVATE,
        )
    private val alias =
        if (namespace == "v1") "swaralara.signing.v1" else "swaralara.signing.$namespace"

    @Synchronized
    fun publicIdentity(): PublicDeviceIdentity {
        HybridConfig.register()
        val id =
            prefs.getString("deviceId", null)?.let(UUID::fromString)
                ?: UUID.randomUUID().also {
                    check(prefs.edit().putString("deviceId", it.toString()).commit())
                }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!store.containsAlias(alias)) {
            // Never silently replace an established signing identity.
            check(!prefs.contains("hpke") && !prefs.contains("hpkeFingerprint")) {
                "SIGNING_KEY_LOST"
            }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
                .apply {
                    initialize(
                        KeyGenParameterSpec.Builder(
                                alias,
                                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                            )
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(
                                java.security.spec.ECGenParameterSpec("secp256r1")
                            )
                            .build()
                    )
                }
                .generateKeyPair()
            store.load(null)
        }
        val handle: KeysetHandle
        val envelope = prefs.getString("hpke", null)
        if (envelope == null) {
            check(!prefs.contains("hpkeFingerprint")) { "HPKE_KEY_LOST" }
            handle =
                KeysetHandle.generateNew(
                    KeyTemplates.get("DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM")
                )
            val stream = ByteArrayOutputStream()
            CleartextKeysetHandle.write(handle, BinaryKeysetWriter.withOutputStream(stream))
            val raw = stream.toByteArray()
            try {
                check(
                    prefs
                        .edit()
                        .putString("hpke", encodeBase64(protector.wrap("device-hpke/$id", raw)))
                        .commit()
                )
            } finally {
                raw.fill(0)
                stream.reset()
            }
        } else {
            val raw = protector.unwrap("device-hpke/$id", decodeBase64(envelope))
            try {
                handle = CleartextKeysetHandle.read(BinaryKeysetReader.withBytes(raw))
            } finally {
                raw.fill(0)
            }
        }
        val publicStream = ByteArrayOutputStream()
        handle.publicKeysetHandle.writeNoSecret(JsonKeysetWriter.withOutputStream(publicStream))
        val hpke = publicStream.toByteArray()
        val spki = store.getCertificate(alias).publicKey.encoded
        val fingerprint = Segments.hex(Segments.hash(hpke))
        val prior = prefs.getString("hpkeFingerprint", null)
        check(prior == null || prior == fingerprint) { "HPKE_KEY_CHANGED" }
        if (prior == null) check(prefs.edit().putString("hpkeFingerprint", fingerprint).commit())
        val proof =
            ByteBuffer.allocate(84)
                .put("SWD2".toByteArray())
                .apply { putUuid(id) }
                .put(Segments.hash(hpke))
                .put(Segments.hash(spki))
                .array()
        return PublicDeviceIdentity(
            id,
            encodeBase64(hpke),
            Segments.hex(Segments.hash(hpke)),
            encodeBase64(spki),
            Segments.hex(Segments.hash(spki)),
            encodeBase64(sign(proof)),
        )
    }

    @Synchronized
    fun sign(payload: ByteArray): ByteArray {
        require(payload.size in 1..65536)
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return Signature.getInstance("SHA256withECDSA")
            .apply {
                initSign(store.getKey(alias, null) as java.security.PrivateKey)
                update(payload)
            }
            .sign()
    }

    fun trustConfirmation(id: UUID): String {
        val device = publicIdentity().deviceId
        return encodeBase64(
            sign(
                ByteBuffer.allocate(36)
                    .put("SWT1".toByteArray())
                    .apply {
                        putUuid(id)
                        putUuid(device)
                    }
                    .array()
            )
        )
    }

    @Synchronized
    internal fun openEnvelope(ciphertext: ByteArray, context: ByteArray): ByteArray {
        val own = publicIdentity()
        val raw =
            protector.unwrap(
                "device-hpke/${own.deviceId}",
                decodeBase64(requireNotNull(prefs.getString("hpke", null))),
            )
        return try {
            Hpke.open(Hpke.privateHandle(raw), ciphertext, context)
        } finally {
            raw.fill(0)
        }
    }
}
