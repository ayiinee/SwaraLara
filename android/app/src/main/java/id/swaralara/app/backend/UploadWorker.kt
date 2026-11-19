package id.swaralara.app.backend

import android.content.Context
import androidx.work.*
import id.swaralara.app.BuildConfig
import id.swaralara.core.CoreRuntime
import kotlinx.coroutines.CancellationException
import java.util.UUID
import java.util.concurrent.TimeUnit

class UploadWorker(context: Context,parameters: WorkerParameters): CoroutineWorker(context,parameters) {
    override suspend fun doWork(): Result {
        val id=runCatching {UUID.fromString(inputData.getString("recordingId"))}.getOrNull()?:return Result.failure()
        val core=CoreRuntime.get(applicationContext)
        return try {
            core.awaitReady()
            val url=BuildConfig.SUPABASE_URL.trimEnd('/')
            val sessions=SessionStore(applicationContext,url)
            val snapshot=core.vault.exportEncryptedSnapshot(id)
            if(snapshot.policyCode=="demo_2of3")return Result.failure()
            if(snapshot.cloudOwnerUserId!=sessions.load()?.userId){core.vault.markSyncFailure(id,"AUTH_REQUIRED");return Result.failure()}
            CloudClient(url,BuildConfig.SUPABASE_PUBLISHABLE_KEY,sessions).sync(snapshot,core.vault::acknowledgeUpload)
            EnvelopeWorker.enqueue(applicationContext,id)
            Result.success()
        } catch(e: CancellationException){throw e}
        catch(e: CloudError) {
            val code=when(e.status){401,403->"AUTH_REQUIRED";409,422->"CONFLICT";else->"REMOTE"}
            core.vault.markSyncFailure(id,code)
            if(e.status in setOf(401,403,409,422))Result.failure() else Result.retry()
        }catch(_:java.io.IOException){core.vault.markSyncFailure(id,"NETWORK");Result.retry()}
        catch(_:Exception){runCatching {core.vault.markSyncFailure(id,"REMOTE")};Result.failure()}
    }
    companion object {
        fun enqueue(context: Context,id: UUID): UUID {
            val request=OneTimeWorkRequestBuilder<UploadWorker>().setInputData(workDataOf("recordingId" to id.toString()))
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL,30,TimeUnit.SECONDS).build()
            WorkManager.getInstance(context).enqueueUniqueWork("swl-upload-$id",ExistingWorkPolicy.KEEP,request)
            return request.id
        }
    }
}
