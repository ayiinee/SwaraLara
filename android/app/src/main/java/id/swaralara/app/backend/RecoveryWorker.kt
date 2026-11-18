package id.swaralara.app.backend

import android.content.Context
import androidx.work.*
import id.swaralara.app.BuildConfig
import id.swaralara.core.CoreRuntime
import id.swaralara.core.M3Json
import id.swaralara.core.RecoveryState
import id.swaralara.core.SyncState
import kotlinx.coroutines.CancellationException
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Polls M3 inbox for this device:
 *  - As a holder: fetches pending my-share and sends ack if not yet acked.
 *  - As an approver: fetches pending access-requests and approves+releases for each recording
 *    where local my-share is stored and user has pre-approved (determined by core policy).
 *
 * This worker does NOT auto-approve; approveAndRelease() is only called if core returns
 * userApproved=true (the user has previously and explicitly approved via UI).
 */
class RecoveryWorker(context: Context, parameters: WorkerParameters) :
    CoroutineWorker(context, parameters) {

    override suspend fun doWork(): Result {
        val core = CoreRuntime.get(applicationContext)
        return try {
            core.awaitReady()
            val url = BuildConfig.SUPABASE_URL.trimEnd('/')
            val sessions = SessionStore(applicationContext, url)
            val client = CloudClient(url, BuildConfig.SUPABASE_PUBLISHABLE_KEY, sessions)

            // 1. Poll my-share for all recordings needing ack
            val recordings = core.vault.observeRecordings()
            // Use a one-shot collect to get current list
            var recordingList = emptyList<id.swaralara.core.RecordingSummary>()
            kotlinx.coroutines.withTimeoutOrNull(5_000) {
                recordings.collect { list ->
                    recordingList = list
                    throw kotlinx.coroutines.CancellationException("collected")
                }
            }

            for (r in recordingList) {
                if (r.recovery == RecoveryState.ENVELOPES_UPLOADED ||
                    r.recovery == RecoveryState.ENVELOPES_QUEUED) {
                    try {
                        val pair = client.getMyShare(r.id) ?: continue
                        val (policy, envelope) = pair
                        val ack = core.keyExchange.receiveShare(policy, envelope)
                        client.ackShare(r.id, ack)
                    } catch (_: Exception) { /* log and continue */ }
                }
            }

            // 2. Poll pending access-requests (as approver/holder)
            try {
                val requests = client.getAccessRequests()
                for (req in requests) {
                    try {
                        // approveAndRelease only if user explicitly approved (userApproved param)
                        // Here we pass userApproved=false → core will return release only if
                        // pre-consent stored. UI-driven approval is handled in MainActivity.
                        val release = core.keyExchange.approveAndRelease(req, userApproved = false)
                        client.approveRelease(req.requestId, release)
                    } catch (_: Exception) { /* log and continue */ }
                }
            } catch (_: Exception) { /* log and continue */ }

            Result.success()
        } catch (e: CancellationException) {
            throw e
        } catch (e: CloudError) {
            if (e.status in setOf(401, 403)) Result.failure() else Result.retry()
        } catch (_: java.io.IOException) {
            Result.retry()
        } catch (_: Exception) {
            Result.failure()
        }
    }

    companion object {
        fun enqueueOnce(context: Context): UUID {
            val request = OneTimeWorkRequestBuilder<RecoveryWorker>()
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 60, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork("swl-recovery-poll", ExistingWorkPolicy.KEEP, request)
            return request.id
        }
    }
}
