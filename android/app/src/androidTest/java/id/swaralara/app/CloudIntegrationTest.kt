package id.swaralara.app

import android.Manifest
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.GrantPermissionRule
import androidx.work.WorkManager
import androidx.work.WorkInfo
import id.swaralara.app.backend.*
import id.swaralara.core.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CloudIntegrationTest {
    @get:Rule val permission: GrantPermissionRule=GrantPermissionRule.grant(Manifest.permission.RECORD_AUDIO)
    private val origin=BuildConfig.SUPABASE_URL.ifBlank { "http://10.0.2.2:8787" }
    private suspend fun finished(manager: WorkManager,id: UUID): WorkInfo = withTimeout(60000) {
        var info: WorkInfo?=null
        while(info?.state?.isFinished!=true) {
            delay(250)
            info=withContext(Dispatchers.IO){manager.getWorkInfoById(id).get()}
        }
        requireNotNull(info)
    }
    private fun fixture(path: String,session: CloudSession,body: JSONObject=JSONObject()): JSONObject {
        val c=URL("$origin/__test__/$path").openConnection() as HttpURLConnection
        try {
            c.requestMethod="POST";c.connectTimeout=15000;c.readTimeout=30000;c.doOutput=true
            c.setRequestProperty("Authorization","Bearer ${session.accessToken}");c.setRequestProperty("Content-Type","application/json")
            c.outputStream.use {it.write(body.toString().toByteArray())};check(c.responseCode==200)
            return JSONObject(c.inputStream.bufferedReader().use {it.readText()})
        }finally{c.disconnect()}
    }
    @Test fun signedDevicePolicyUploadRetryReceiptAndIsolation() = runBlocking {
        val context=ApplicationProvider.getApplicationContext<android.content.Context>()
        val args=InstrumentationRegistry.getArguments()
        val password=requireNotNull(args.getString("fixturePassword")) {"Start test-only contract server first"}
        val key=requireNotNull(args.getString("fixturePublishableKey"))
        val core=CoreRuntime.get(context);core.awaitReady()
        val store=SessionStore(context,origin);store.clear()
        val client=CloudClient(origin,key,store,true)
        val scenario=ActivityScenario.launch(MainActivity::class.java)
        try {
            val owner=client.login("owner@test.local",password)
            SessionStore(context,origin).clear()
            assertFalse(store.replace(owner.refreshToken,owner))
            assertNull(store.load());store.save(owner)
            val identity=core.identity.publicIdentity();client.register(identity)
            store.save(owner.copy(expiresAt=0));client.api("/devices/me")
            assertNotEquals(owner.refreshToken,store.load()!!.refreshToken)
            val paired=fixture("pair",owner,JSONObject().put("ownerDeviceId",identity.deviceId)).getJSONObject("data")
            var links=client.links()
            val link=(0 until links.length()).map {links.getJSONObject(it)}.single {it.getString("id")==paired.getString("linkId")}
            client.confirm(link,core.identity);links=client.links()
            val confirmed=(0 until links.length()).map {links.getJSONObject(it)}.single {it.getString("id")==link.getString("id")}
            assertEquals("active",confirmed.getString("state"));assertTrue(store.pinned(confirmed))
            val h=confirmed.getJSONObject("holderDevice")
            val policy=CloudCapturePolicy(owner.userId,identity.deviceId,"owner_required_2of2",listOf(
                CloudMember(1,owner.userId,identity.deviceId,identity.hpkeFingerprint,identity.signingFingerprint),
                CloudMember(2,UUID.fromString(confirmed.getString("holder_user_id")),UUID.fromString(h.getString("id")),h.getString("hpke_fingerprint"),h.getString("signing_fingerprint"))))
            val id=core.recorder.start(CaptureConfig(cloudPolicy=policy))
            withTimeout(30000){core.recorder.state.first {it.capture==CaptureState.RECORDING};core.recorder.state.first {it.savedSegments>=1}}
            delay(400);core.recorder.stop()
            val snapshot=core.vault.exportEncryptedSnapshot(id)
            assertNotNull(snapshot.cloudRegistrationJson)
            val originals=snapshot.segments.map {it.file.readBytes()}
            val bad=UploadReceipt(id,0,"0".repeat(64),1)
            try {core.vault.acknowledgeUpload(bad);fail("Accepted forged receipt")}catch(_:IllegalArgumentException){}
            fixture("interrupt",owner)
            try {client.sync(snapshot,core.vault::acknowledgeUpload);fail("Expected interrupted commit")}
            catch(e:CloudError){assertEquals(503,e.status)}
            core.vault.markSyncFailure(id,"NETWORK");assertTrue(core.vault.inspect(id).passed)
            try {client.sync(snapshot){throw java.io.IOException("Simulated lost acknowledgment")};fail("Expected lost receipt")}
            catch(_:java.io.IOException){}
            core.vault.markSyncFailure(id,"AUTH_REQUIRED")
            assertEquals(SyncState.NEEDS_AUTH,core.vault.observeRecordings().first().single {it.id==id}.sync)
            assertTrue(core.vault.inspect(id).passed)
            client.sync(snapshot,core.vault::acknowledgeUpload)
            client.sync(core.vault.exportEncryptedSnapshot(id),core.vault::acknowledgeUpload)
            val summary=core.vault.observeRecordings().first().single {it.id==id}
            assertEquals(SyncState.SYNCED,summary.sync)
            // M3 may already distribute ciphertext; the simulated holder has not decrypted/acked it.
            assertTrue(summary.recovery in setOf(RecoveryState.DEGRADED,RecoveryState.ENVELOPES_QUEUED,RecoveryState.ENVELOPES_UPLOADED))
            snapshot.segments.forEachIndexed {i,s->assertArrayEquals(originals[i],s.file.readBytes())}
            val stats=fixture("counts",owner).getJSONObject("data")
            assertEquals(snapshot.segments.size,stats.getInt("segments"));assertEquals(snapshot.segments.size,stats.getInt("objects"))
            assertEquals(origin,BuildConfig.SUPABASE_URL)
            val workManager=WorkManager.getInstance(context)
            val work=finished(workManager,UploadWorker.enqueue(context,id))
            assertEquals(WorkInfo.State.SUCCEEDED,work.state)
            client.login("outsider@test.local",password)
            try {client.api("/recordings/$id");fail("Cross-user read accepted")}catch(e:CloudError){assertEquals(404,e.status)}
            store.save(owner.copy(expiresAt=0,refreshToken="invalid-refresh"))
            try {client.api("/devices/me");fail("Expired session accepted")}catch(e:CloudError){assertEquals(401,e.status)}
            assertEquals(WorkInfo.State.FAILED,finished(workManager,UploadWorker.enqueue(context,id)).state)
            assertEquals(SyncState.NEEDS_AUTH,core.vault.observeRecordings().first().single {it.id==id}.sync)
            assertTrue(core.vault.inspect(id).passed)
            val local=core.recorder.start(CaptureConfig())
            withTimeout(30000){core.recorder.state.first {it.capture==CaptureState.RECORDING && it.id==local};core.recorder.state.first {it.savedSegments>=1}}
            core.recorder.stop()
            assertEquals(SyncState.LOCAL_ONLY,core.vault.observeRecordings().first().single {it.id==local}.sync)
            assertTrue(core.vault.inspect(local).passed)
        }finally {
            if(core.recorder.state.value.busy)core.recorder.stop()
            core.playback.release();scenario.close();store.clear()
        }
    }
}
