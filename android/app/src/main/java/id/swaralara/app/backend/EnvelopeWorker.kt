package id.swaralara.app.backend

import android.content.Context
import androidx.work.*
import id.swaralara.app.BuildConfig
import id.swaralara.core.CoreRuntime
import id.swaralara.core.EnvelopeUploadReceipt
import kotlinx.coroutines.CancellationException
import java.util.UUID
import java.util.concurrent.TimeUnit

class EnvelopeWorker(context: Context, parameters: WorkerParameters) :
    CoroutineWorker(context, parameters) {

    override suspend fun doWork(): Result {
        val id = runCatching {
            UUID.fromString(inputData.getString("recordingId"))
        }.getOrNull() ?: return Result.failure()
        val core = CoreRuntime.get(applicationContext)
        return try {
            core.awaitReady()
            val url = BuildConfig.SUPABASE_URL.trimEnd('/')
            val sessions = SessionStore(applicationContext, url)
            val client = CloudClient(url, BuildConfig.SUPABASE_PUBLISHABLE_KEY, sessions)
            // Prepare envelopes (no DEK/private key leaves core)
            val policy = core.keyExchange.exportPolicy(id)
            val envelopes = core.keyExchange.prepareDistribution(id)
            if (envelopes.isEmpty()) return Result.failure()
            // Upload all envelopes in one request
            val receipts = client.uploadEnvelopes(id, envelopes)
            // Acknowledge each receipt through core (updates local DB)
            receipts.forEach { receipt -> core.keyExchange.acknowledgeEnvelopeUpload(receipt) }
            Result.success()
        } catch (e: CancellationException) {
            throw e
        } catch (e: CloudError) {
            if (e.status in setOf(401, 403, 409, 422)) Result.failure()
            else Result.retry()
        } catch (_: java.io.IOException) {
            Result.retry()
        } catch (_: Exception) {
            Result.failure()
        }
    }

    companion object {
        fun enqueue(context: Context, id: UUID): UUID {
            val request = OneTimeWorkRequestBuilder<EnvelopeWorker>()
                .setInputData(workDataOf("recordingId" to id.toString()))
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork("swl-envelopes-$id", ExistingWorkPolicy.KEEP, request)
            return request.id
        }
    }
}
