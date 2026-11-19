package id.swaralara.app.backend

import android.content.Context
import androidx.work.*
import id.swaralara.app.BuildConfig
import id.swaralara.core.*
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException

/** Receives ciphertext and signed acknowledgments. Never approves or releases shares. */
class RecoveryWorker(context: Context, parameters: WorkerParameters) :
    CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val url = BuildConfig.SUPABASE_URL.trimEnd('/')
        val sessions = SessionStore(applicationContext, url)
        if (url.isBlank() || sessions.load() == null) return Result.success()
        return try {
            val core = CoreRuntime.get(applicationContext)
            core.awaitReady()
            M3Sync.refresh(core, CloudClient(url, BuildConfig.SUPABASE_PUBLISHABLE_KEY, sessions))
            Result.success()
        } catch (e: CancellationException) {
            throw e
        } catch (e: CloudError) {
            if (e.status in setOf(401, 403, 409, 422)) Result.failure(workDataOf("code" to e.code))
            else Result.retry()
        } catch (_: java.io.IOException) {
            Result.retry()
        } catch (_: Exception) {
            Result.failure(workDataOf("code" to "M3_VERIFICATION_REQUIRED"))
        }
    }

    companion object {
        private fun constraints() =
            Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()

        fun enqueueOnce(context: Context): UUID {
            val work =
                OneTimeWorkRequestBuilder<RecoveryWorker>()
                    .setConstraints(constraints())
                    .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                    .build()
            WorkManager.getInstance(context)
                .enqueueUniqueWork("swl-recovery-poll", ExistingWorkPolicy.KEEP, work)
            return work.id
        }

        fun schedule(context: Context) {
            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(
                    "swl-recovery-periodic",
                    ExistingPeriodicWorkPolicy.KEEP,
                    PeriodicWorkRequestBuilder<RecoveryWorker>(15, TimeUnit.MINUTES)
                        .setConstraints(constraints())
                        .build(),
                )
        }
    }
}
