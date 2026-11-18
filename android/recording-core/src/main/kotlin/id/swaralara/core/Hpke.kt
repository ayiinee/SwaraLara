package id.swaralara.core

import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.InsecureSecretKeyAccess
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.TinkJsonProtoKeysetFormat
import com.google.crypto.tink.TinkProtoKeysetFormat
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.proto.HpkePublicKey
import com.google.crypto.tink.proto.KeyData
import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.proto.Keyset
import com.google.crypto.tink.proto.OutputPrefixType

internal object Hpke {
    private const val TEMPLATE = "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM"

    fun fresh(): KeysetHandle {
        HybridConfig.register()
        return KeysetHandle.generateNew(KeyTemplates.get(TEMPLATE))
    }

    fun publicBytes(handle: KeysetHandle): ByteArray =
        TinkJsonProtoKeysetFormat.serializeKeysetWithoutSecret(handle.publicKeysetHandle)
            .toByteArray(Charsets.UTF_8)

    fun privateBytes(handle: KeysetHandle): ByteArray =
        TinkProtoKeysetFormat.serializeKeyset(handle, InsecureSecretKeyAccess.get())

    fun privateHandle(bytes: ByteArray): KeysetHandle =
        TinkProtoKeysetFormat.parseKeyset(bytes, InsecureSecretKeyAccess.get())

    fun publicHandle(bytes: ByteArray): KeysetHandle {
        require(bytes.size in 1..4096)
        HybridConfig.register()
        // Tink's no-secret parser is authoritative. Inspect the binary public key too to pin the
        // suite and prefix.
        val handle =
            TinkJsonProtoKeysetFormat.parseKeysetWithoutSecret(String(bytes, Charsets.UTF_8))
        val keyset = Keyset.parseFrom(TinkProtoKeysetFormat.serializeKeysetWithoutSecret(handle))
        require(keyset.keyCount == 1)
        val key = keyset.getKey(0)
        require(
            key.keyId == keyset.primaryKeyId &&
                key.status == KeyStatusType.ENABLED &&
                key.outputPrefixType == OutputPrefixType.TINK
        )
        require(
            key.keyData.keyMaterialType == KeyData.KeyMaterialType.ASYMMETRIC_PUBLIC &&
                key.keyData.typeUrl == "type.googleapis.com/google.crypto.tink.HpkePublicKey"
        )
        val hpke = HpkePublicKey.parseFrom(key.keyData.value)
        require(
            hpke.version == 0 &&
                hpke.params.kemValue == 1 &&
                hpke.params.kdfValue == 1 &&
                hpke.params.aeadValue == 2 &&
                hpke.publicKey.size() == 32
        )
        return handle
    }

    fun seal(public: ByteArray, plaintext: ByteArray, context: ByteArray): ByteArray =
        publicHandle(public)
            .getPrimitive(RegistryConfiguration.get(), HybridEncrypt::class.java)
            .encrypt(plaintext, context)

    fun open(privateKey: KeysetHandle, ciphertext: ByteArray, context: ByteArray): ByteArray {
        require(ciphertext.size in 53..8192 && context.size in 1..4096)
        return privateKey
            .getPrimitive(RegistryConfiguration.get(), HybridDecrypt::class.java)
            .decrypt(ciphertext, context)
    }
}
