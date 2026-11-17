package id.swaralara.crypto

import org.bouncycastle.crypto.threshold.ShamirSecretSplitter
import org.bouncycastle.crypto.threshold.ShamirSplitSecret
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID

/** Internal algorithm payload; never put in UI state, a public Android DTO, or a log. */
class DemoShare(val recordingId: UUID, val index: Int, val value: ByteArray) {
    fun clear() = value.fill(0)
}

object DemoSharing {
    private val algorithm = ShamirSecretSplitter.Algorithm.AES
    private val mode = ShamirSecretSplitter.Mode.Table
    fun split(id: UUID, secret: ByteArray): List<DemoShare> {
        require(secret.size == 32)
        val shares = ShamirSecretSplitter(algorithm, mode, 32, SecureRandom()).resplit(secret, 2, 3).secretShares
        // BC 1.83 allocates this array by secret length (32), with only n entries populated.
        // Keep the requested coordinates, never infer coordinates by filtering null entries.
        return shares.take(3).mapIndexed { i, s -> DemoShare(id, i + 1, requireNotNull(s).encoded) }
    }
    fun recover(id: UUID, shares: List<DemoShare>): ByteArray {
        require(shares.size in 2..3 && shares.map { it.index }.distinct().size == shares.size)
        require(shares.all { it.recordingId == id && it.index in 1..3 && it.value.size == 32 })
        return ShamirSplitSecret(algorithm, mode,
            shares.map { ShamirSplitSecretShare(it.value, it.index) }.toTypedArray()).secret
    }
    // M1-only codec SWD1 + UUID + threshold/count/x + 32 y bytes. No integrated holder/policy binding.
    fun encode(share: DemoShare): ByteArray {
        require(share.index in 1..3 && share.value.size == 32)
        return ByteBuffer.allocate(55).putInt(0x53574431)
            .putLong(share.recordingId.mostSignificantBits).putLong(share.recordingId.leastSignificantBits)
            .put(2.toByte()).put(3.toByte()).put(share.index.toByte()).put(share.value).array()
    }
    fun decode(bytes: ByteArray): DemoShare {
        require(bytes.size == 55)
        val b = ByteBuffer.wrap(bytes)
        require(b.int == 0x53574431)
        val id = UUID(b.long, b.long)
        require(b.get() == 2.toByte() && b.get() == 3.toByte())
        val x = b.get().toInt()
        require(x in 1..3)
        return DemoShare(id, x, ByteArray(32).also(b::get))
    }
}
