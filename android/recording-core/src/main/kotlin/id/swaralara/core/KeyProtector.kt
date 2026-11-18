package id.swaralara.core

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class KeyProtector(private val alias: String = "swaralara.local-kek.v1") {
    companion object {
        fun forRecording(id: java.util.UUID) = KeyProtector("swaralara.recording-kek.v2.$id")

        fun forRequest(id: java.util.UUID) = KeyProtector("swaralara.request-kek.v1.$id")

        fun destroyRecordingKey(id: java.util.UUID) {
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                deleteEntry("swaralara.recording-kek.v2.$id")
            }
        }

        fun destroyRequestKey(id: java.util.UUID) {
            KeyStore.getInstance("AndroidKeyStore").apply {
                load(null)
                deleteEntry("swaralara.request-kek.v1.$id")
            }
        }
    }

    @Synchronized
    private fun key(create: Boolean = true): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let {
            return it
        }
        check(create) { "KEYSTORE_KEY_UNAVAILABLE" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply {
                init(
                    KeyGenParameterSpec.Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                        )
                        .setKeySize(256)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build()
                )
            }
            .generateKey()
    }

    fun wrap(id: String, raw: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD("swaralara/local-dek/v1/$id".toByteArray(Charsets.UTF_8))
        return cipher.iv + cipher.doFinal(raw)
    }

    fun unwrap(id: String, envelope: ByteArray): ByteArray {
        require(envelope.size in 28..65564)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(false),
            GCMParameterSpec(128, envelope.copyOfRange(0, 12)),
        )
        cipher.updateAAD("swaralara/local-dek/v1/$id".toByteArray(Charsets.UTF_8))
        return cipher.doFinal(envelope, 12, envelope.size - 12)
    }
}
