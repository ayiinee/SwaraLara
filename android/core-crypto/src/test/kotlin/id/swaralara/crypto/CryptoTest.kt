package id.swaralara.crypto

import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class CryptoTest {
    private val id = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val key = ByteArray(32) { it.toByte() }
    private fun rejects(action: () -> Unit) {
        try { action(); fail("Accepted invalid input") } catch (e: Exception) { /* expected */ }
    }
    @Test fun headerVectorAndRoundTrip() {
        val h = SegmentHeader(id, 0, 16000, 2, Segments.nonce(ByteArray(8) { it.toByte() }, 0), ByteArray(32))
        val expected = "53574c3100112233445566778899aabbccddeeff0000000000003e80010100000002000102030405060700000000" + "00".repeat(32) + "00000014"
        assertEquals(expected, Segments.hex(Segments.encodeHeader(h)))
        assertEquals(82, Segments.encodeHeader(h).size)
        val pcm = byteArrayOf(1,2,3,4)
        val encrypted = Segments.encrypt(key, h, pcm)
        assertArrayEquals(pcm, Segments.decryptVerified(key, encrypted, id, 0, ByteArray(32)))
    }
    @Test fun tamperEveryByteTruncateAppendAndWrongKeyRejected() {
        val bytes = SegmentSession(id, key.copyOf(), 16000).use { it.encrypt(ByteArray(80) { it.toByte() }) }
        bytes.indices.forEach { at ->
            val corrupt = bytes.copyOf(); corrupt[at] = (corrupt[at].toInt() xor 1).toByte()
            rejects { Segments.decryptVerified(key, corrupt, id, 0, ByteArray(32)) }
        }
        for (length in 0 until bytes.size) rejects { Segments.parse(bytes.copyOf(length)) }
        rejects { Segments.parse(bytes + byteArrayOf(0)) }
        rejects { Segments.decryptVerified(ByteArray(32), bytes, id, 0, ByteArray(32)) }
    }
    @Test fun uniqueNonceChainAndBinding() {
        SegmentSession(id, key.copyOf(), 16000).use { session ->
            val first = session.encrypt(ByteArray(20))
            val second = session.encrypt(ByteArray(6))
            assertFalse(Segments.parse(first).nonce.contentEquals(Segments.parse(second).nonce))
            assertArrayEquals(ByteArray(6), Segments.decryptVerified(key, second, id, 1, Segments.hash(first)))
            rejects { Segments.decryptVerified(key, second, id, 0, ByteArray(32)) }
            rejects { Segments.decryptVerified(key, first, UUID.randomUUID(), 0, ByteArray(32)) }
            rejects { Segments.decryptVerified(key, second, id, 1, ByteArray(32)) }
        }
        rejects { Segments.nonce(ByteArray(8), 0x1_0000_0000L) }
        rejects { Segments.nonce(ByteArray(8), -1) }
    }
    @Test fun allShamirPairsAndCodec() {
        repeat(8) {
            val shares = DemoSharing.split(id, key)
            try {
                for ((a,b) in listOf(0 to 1, 0 to 2, 1 to 2)) {
                    val decoded = listOf(shares[a], shares[b]).map { DemoSharing.decode(DemoSharing.encode(it)) }
                    val recovered = DemoSharing.recover(id, decoded)
                    assertArrayEquals(key, recovered); recovered.fill(0); decoded.forEach { it.clear() }
                }
                rejects { DemoSharing.recover(id, listOf(shares[0])) }
                rejects { DemoSharing.recover(id, listOf(shares[0], shares[0])) }
                rejects { DemoSharing.recover(UUID.randomUUID(), shares.take(2)) }
                rejects { DemoSharing.recover(id, listOf(shares[0], DemoShare(id, 2, ByteArray(31)))) }
                rejects { DemoSharing.decode(ByteArray(55)) }
                rejects { DemoSharing.decode(DemoSharing.encode(shares[0]) + byteArrayOf(0)) }
            } finally { shares.forEach { it.clear() } }
        }
    }
    @Test fun partialReadsTailAndIncompleteFrame() {
        val output = mutableListOf<ByteArray>()
        PcmSegmenter(8) { output += it.copyOf() }.use { segmenter ->
            val input = ByteArray(22) { it.toByte() }
            var offset = 0
            for (length in listOf(1,3,7,2,9)) { segmenter.append(input.copyOfRange(offset, offset+length), length); offset += length }
            segmenter.finish()
            assertEquals(listOf(8,8,6), output.map { it.size })
            assertArrayEquals(input, output.fold(byteArrayOf()) { acc, part -> acc + part })
        }
        PcmSegmenter(8) {}.use { it.append(byteArrayOf(1),1); rejects { it.finish() } }
    }
    @Test fun closedSessionCannotReuseKeyNonce() {
        val session = SegmentSession(id, key.copyOf(), 16000)
        session.close(); rejects { session.encrypt(ByteArray(4)) }
    }
}
