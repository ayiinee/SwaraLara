package id.swaralara.crypto

import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class ThresholdSharesTest {
    @Test
    fun integratedPoliciesRecoverEveryAllowedPairAndKeepBindings() {
        for (policy in ThresholdPolicy.entries) {
            val id = UUID.randomUUID()
            val hash = "a".repeat(64)
            val secret = ByteArray(32) { it.toByte() }
            val holders = List(policy.count) { UUID.randomUUID() }
            val shares = ThresholdShares.split(id, hash, policy, holders, secret)
            try {
                for (a in shares.indices) for (b in a + 1 until shares.size) {
                    val encoded = ThresholdShares.encode(shares[a])
                    val decoded = ThresholdShares.decode(encoded)
                    try {
                        assertEquals(holders[a], decoded.holderDeviceId)
                        assertArrayEquals(
                            secret,
                            ThresholdShares.recover(id, hash, policy, listOf(decoded, shares[b])),
                        )
                    } finally {
                        decoded.close()
                        encoded.fill(0)
                    }
                }
            } finally {
                shares.forEach { it.close() }
                secret.fill(0)
            }
        }
    }

    @Test
    fun insufficientDuplicateForeignPolicyAndMalformedSharesAreRejected() {
        val id = UUID.randomUUID()
        val hash = "b".repeat(64)
        val p = ThresholdPolicy.RECOVERY_2OF3
        val shares =
            ThresholdShares.split(id, hash, p, List(3) { UUID.randomUUID() }, ByteArray(32))
        try {
            for (bad in listOf(listOf(shares[0]), listOf(shares[0], shares[0]))) {
                assertThrows(IllegalArgumentException::class.java) {
                    ThresholdShares.recover(id, hash, p, bad)
                }
            }
            assertThrows(IllegalArgumentException::class.java) {
                ThresholdShares.recover(UUID.randomUUID(), hash, p, shares.take(2))
            }
            assertThrows(IllegalArgumentException::class.java) {
                ThresholdShares.recover(id, "c".repeat(64), p, shares.take(2))
            }
            assertThrows(IllegalArgumentException::class.java) {
                ThresholdShares.recover(
                    id,
                    hash,
                    ThresholdPolicy.OWNER_REQUIRED_2OF2,
                    shares.take(2),
                )
            }
            val encoded = ThresholdShares.encode(shares[0])
            assertThrows(IllegalArgumentException::class.java) {
                ThresholdShares.decode(encoded + byteArrayOf(0))
            }
            encoded[0] = 0
            assertThrows(IllegalArgumentException::class.java) { ThresholdShares.decode(encoded) }
            assertEquals("BoundShare(REDACTED)", shares[0].toString())
        } finally {
            shares.forEach { it.close() }
        }
    }
}
