package id.swaralara.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.UUID
import org.bouncycastle.crypto.threshold.ShamirSecretSplitter
import org.bouncycastle.crypto.threshold.ShamirSplitSecret
import org.bouncycastle.crypto.threshold.ShamirSplitSecretShare

enum class ThresholdPolicy(val code: Int, val count: Int) {
    OWNER_REQUIRED_2OF2(1, 2),
    RECOVERY_2OF3(2, 3),
}

/** Secret algorithm object, confined to core code. Never use as an Android/public transport DTO. */
class BoundShare
internal constructor(
    val recordingId: UUID,
    val policyHash: String,
    val policy: ThresholdPolicy,
    val index: Int,
    val holderDeviceId: UUID,
    internal val secret: ByteArray,
) : AutoCloseable {
    override fun close() = secret.fill(0)

    override fun toString() = "BoundShare(REDACTED)"
}

/** BC 1.83 AES-basis GF(256), shamir-bc-gf256-v1; distinct from the M1 demo codec. */
object ThresholdShares {
    private val algorithm = ShamirSecretSplitter.Algorithm.AES
    private val mode = ShamirSecretSplitter.Mode.Table

    private fun validHash(hash: String) = require(hash.matches(Regex("[0-9a-f]{64}")))

    fun split(
        id: UUID,
        hash: String,
        policy: ThresholdPolicy,
        holders: List<UUID>,
        key: ByteArray,
    ): List<BoundShare> {
        validHash(hash)
        require(
            key.size == 32 &&
                holders.size == policy.count &&
                holders.distinct().size == holders.size
        )
        val generated =
            ShamirSecretSplitter(algorithm, mode, 32, SecureRandom())
                .resplit(key, 2, policy.count)
                .secretShares
        return (0 until policy.count).map { i ->
            BoundShare(id, hash, policy, i + 1, holders[i], requireNotNull(generated[i]).encoded)
        }
    }

    fun encode(share: BoundShare): ByteArray {
        validHash(share.policyHash)
        require(share.index in 1..share.policy.count && share.secret.size == 32)
        return ByteBuffer.allocate(104)
            .apply {
                putInt(0x53574231)
                putLong(share.recordingId.mostSignificantBits)
                putLong(share.recordingId.leastSignificantBits)
                put(share.policyHash.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
                put(share.policy.code.toByte())
                put(2.toByte())
                put(share.policy.count.toByte())
                put(share.index.toByte())
                putLong(share.holderDeviceId.mostSignificantBits)
                putLong(share.holderDeviceId.leastSignificantBits)
                put(share.secret)
            }
            .array()
    }

    fun decode(bytes: ByteArray): BoundShare {
        require(bytes.size == 104)
        val b = ByteBuffer.wrap(bytes)
        require(b.int == 0x53574231)
        val id = UUID(b.long, b.long)
        val hash = Segments.hex(ByteArray(32).also(b::get))
        val code = b.get().toInt()
        val policy = ThresholdPolicy.entries.single { it.code == code }
        require(b.get().toInt() == 2 && b.get().toInt() == policy.count)
        val index = b.get().toInt()
        require(index in 1..policy.count)
        val holder = UUID(b.long, b.long)
        return BoundShare(id, hash, policy, index, holder, ByteArray(32).also(b::get))
    }

    fun recover(
        id: UUID,
        hash: String,
        policy: ThresholdPolicy,
        shares: List<BoundShare>,
    ): ByteArray {
        validHash(hash)
        require(
            shares.size in 2..policy.count && shares.map { it.index }.distinct().size == shares.size
        )
        require(
            shares.all {
                it.recordingId == id &&
                    it.policyHash == hash &&
                    it.policy == policy &&
                    it.index in 1..policy.count &&
                    it.secret.size == 32
            }
        )
        if (policy == ThresholdPolicy.OWNER_REQUIRED_2OF2) require(shares.any { it.index == 1 })
        return ShamirSplitSecret(
                algorithm,
                mode,
                shares.map { ShamirSplitSecretShare(it.secret, it.index) }.toTypedArray(),
            )
            .secret
    }
}
