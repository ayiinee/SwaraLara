package id.swaralara.core

import java.util.UUID
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * Only short-lived verified DEKs, never serialized; wiped on expiry, cancellation, release or
 * background.
 */
internal class RecoverySessions(private val now: () -> Long = System::currentTimeMillis) {
    private class Lease(
        val requestId: UUID,
        val key: ByteArray,
        val expiresAt: Long,
        var task: ScheduledFuture<*>? = null,
    )

    private val leases = mutableMapOf<UUID, Lease>()

    companion object {
        private val expiry =
            ScheduledThreadPoolExecutor(1) { runnable ->
                    Thread(runnable, "swl-key-expiry").apply { isDaemon = true }
                }
                .apply { removeOnCancelPolicy = true }
    }

    @Synchronized
    fun hold(recordingId: UUID, requestId: UUID, key: ByteArray, expiresAt: Long) {
        require(key.size == 32 && expiresAt > now())
        clearRecording(recordingId)
        val lease = Lease(requestId, key.copyOf(), expiresAt)
        leases[recordingId] = lease
        lease.task =
            expiry.schedule({ clearRequest(requestId) }, expiresAt - now(), TimeUnit.MILLISECONDS)
    }

    @Synchronized
    fun copy(recordingId: UUID): ByteArray? {
        val lease = leases[recordingId] ?: return null
        if (now() >= lease.expiresAt) {
            clearRecording(recordingId)
            return null
        }
        return lease.key.copyOf()
    }

    @Synchronized
    fun requireAvailable(recordingId: UUID) {
        val key = copy(recordingId) ?: error("KEY_RECOVERY_REQUIRED")
        key.fill(0)
    }

    @Synchronized
    fun clearRequest(requestId: UUID) {
        leases.filterValues { it.requestId == requestId }.keys.toList().forEach(::clearRecording)
    }

    @Synchronized
    fun clearRecording(recordingId: UUID) {
        leases.remove(recordingId)?.let {
            it.task?.cancel(false)
            it.key.fill(0)
        }
    }

    @Synchronized
    fun clearAll() {
        leases.keys.toList().forEach(::clearRecording)
    }
}
