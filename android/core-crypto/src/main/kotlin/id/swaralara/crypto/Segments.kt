package id.swaralara.crypto

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class SegmentHeader(
    val recordingId: UUID,
    val index: Long,
    val sampleRate: Int,
    val sampleCount: Int,
    val nonce: ByteArray,
    val previousObjectHash: ByteArray,
) {
    val ciphertextLength: Int get() = Math.addExact(Math.multiplyExact(sampleCount, 2), 16)
}

object Segments {
    const val HEADER_SIZE = 82
    const val MAX_FRAMES = 96_000 * 2
    const val MAX_OBJECT_BYTES = HEADER_SIZE + MAX_FRAMES * 2 + 16
    fun hash(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
    fun nonce(prefix: ByteArray, index: Long): ByteArray {
        require(prefix.size == 8 && index in 0..0xffff_ffffL)
        return ByteBuffer.allocate(12).put(prefix).putInt(index.toInt()).array()
    }
    fun encodeHeader(h: SegmentHeader): ByteArray {
        require(h.index in 0..0xffff_ffffL)
        require(h.sampleRate in setOf(16000, 44100, 48000))
        require(h.sampleCount in 1..MAX_FRAMES)
        require(h.nonce.size == 12 && h.previousObjectHash.size == 32)
        require(ByteBuffer.wrap(h.nonce, 8, 4).int.toLong().and(0xffff_ffffL) == h.index)
        require(h.index != 0L || h.previousObjectHash.all { it == 0.toByte() })
        return ByteBuffer.allocate(HEADER_SIZE)
            .put(byteArrayOf(83, 87, 76, 49))
            .putLong(h.recordingId.mostSignificantBits).putLong(h.recordingId.leastSignificantBits)
            .putInt(h.index.toInt()).putInt(h.sampleRate).put(1.toByte()).put(1.toByte())
            .putInt(h.sampleCount).put(h.nonce).put(h.previousObjectHash).putInt(h.ciphertextLength).array()
    }
    fun parse(bytes: ByteArray): SegmentHeader {
        require(bytes.size in (HEADER_SIZE + 18)..MAX_OBJECT_BYTES) { "SEGMENT_SIZE" }
        val b = ByteBuffer.wrap(bytes)
        require(ByteArray(4).also(b::get).contentEquals(byteArrayOf(83,87,76,49))) { "MAGIC" }
        val id = UUID(b.long, b.long)
        val index = b.int.toLong().and(0xffff_ffffL)
        val rate = b.int
        require(b.get() == 1.toByte() && b.get() == 1.toByte()) { "AUDIO_FORMAT" }
        val frames = b.int
        val h = SegmentHeader(id, index, rate, frames, ByteArray(12).also(b::get), ByteArray(32).also(b::get))
        val declared = b.int
        encodeHeader(h) // validate before allocation/decryption
        require(declared == h.ciphertextLength && bytes.size == HEADER_SIZE + declared) { "LENGTH" }
        return h
    }
    fun encrypt(key: ByteArray, header: SegmentHeader, pcm: ByteArray): ByteArray {
        require(key.size == 32 && pcm.size == header.sampleCount * 2)
        val aad = encodeHeader(header)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, header.nonce))
        cipher.updateAAD(aad)
        return aad + cipher.doFinal(pcm)
    }
    fun decryptVerified(key: ByteArray, bytes: ByteArray, id: UUID, index: Long, previousHash: ByteArray): ByteArray {
        require(key.size == 32)
        val h = parse(bytes)
        require(h.recordingId == id && h.index == index && h.previousObjectHash.contentEquals(previousHash)) { "BINDING_CHAIN" }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, h.nonce))
        cipher.updateAAD(bytes, 0, HEADER_SIZE)
        return cipher.doFinal(bytes, HEADER_SIZE, h.ciphertextLength)
    }
}

/** One instance per session. An encryption attempt consumes its index even if persistence fails. */
class SegmentSession(val id: UUID, private val key: ByteArray, val sampleRate: Int, random: SecureRandom = SecureRandom()) : AutoCloseable {
    private val prefix = ByteArray(8).also(random::nextBytes)
    private var nextIndex = 0L
    private var previousHash = ByteArray(32)
    private var closed = false
    @Synchronized fun encrypt(pcm: ByteArray): ByteArray {
        check(!closed && nextIndex <= 0xffff_ffffL)
        require(pcm.isNotEmpty() && pcm.size % 2 == 0)
        val index = nextIndex++
        try {
            val result = Segments.encrypt(key, SegmentHeader(id, index, sampleRate, pcm.size / 2,
                Segments.nonce(prefix, index), previousHash), pcm)
            previousHash = Segments.hash(result)
            return result
        } catch (e: Exception) { close(); throw e }
    }
    @Synchronized override fun close() { closed = true; key.fill(0); prefix.fill(0) }
}
