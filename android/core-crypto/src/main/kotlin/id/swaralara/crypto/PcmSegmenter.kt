package id.swaralara.crypto

/** Arbitrary read boundaries, including odd-byte partial reads. The final frame must be complete. */
class PcmSegmenter(private val segmentBytes: Int, private val emit: (ByteArray) -> Unit) : AutoCloseable {
    private val buffer = ByteArray(segmentBytes)
    private var used = 0
    init { require(segmentBytes > 0 && segmentBytes % 2 == 0) }
    fun append(bytes: ByteArray, length: Int) {
        require(length in 0..bytes.size)
        var offset = 0
        while (offset < length) {
            val size = minOf(segmentBytes - used, length - offset)
            bytes.copyInto(buffer, used, offset, offset + size)
            used += size; offset += size
            if (used == segmentBytes) { flush() }
        }
    }
    private fun flush() {
        val pcm = buffer.copyOf(used)
        try { emit(pcm) } finally { pcm.fill(0); buffer.fill(0); used = 0 }
    }
    fun finish() { require(used % 2 == 0) { "INCOMPLETE_PCM_FRAME" }; if (used > 0) flush() }
    override fun close() { buffer.fill(0); used = 0 }
}
