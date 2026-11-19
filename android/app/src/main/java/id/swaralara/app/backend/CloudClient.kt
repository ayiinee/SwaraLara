package id.swaralara.app.backend

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import id.swaralara.app.BuildConfig
import id.swaralara.core.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class CloudError(val status: Int,val code: String): Exception(code)
data class CloudSession(val userId: UUID,val accessToken: String,val refreshToken: String,val expiresAt: Long)
class SessionStore(context: Context,private val origin: String) {
    companion object { internal val refreshLock=Any(); private val sessionLock=Any() }
    private val prefs=context.applicationContext.getSharedPreferences("swl-session-v1",Context.MODE_PRIVATE)
    private fun key(): javax.crypto.SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        (store.getKey("swl.session.v1",null) as? javax.crypto.SecretKey)?.let {return it}
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder("swl.session.v1",KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
        }.generateKey()
    }
    fun save(session: CloudSession) = synchronized(sessionLock) {
        val plain=JSONObject().put("userId",session.userId).put("accessToken",session.accessToken).put("refreshToken",session.refreshToken).put("expiresAt",session.expiresAt).toString().toByteArray()
        try {
            val c=Cipher.getInstance("AES/GCM/NoPadding").apply {init(Cipher.ENCRYPT_MODE,key());updateAAD(origin.toByteArray())}
            check(prefs.edit().putString("session",encodeBase64(c.iv+c.doFinal(plain))).commit())
        } finally {plain.fill(0)}
    }
    fun load(): CloudSession? = synchronized(sessionLock) {
        val envelope=prefs.getString("session",null)?:return@synchronized null
        try {
            val bytes=decodeBase64(envelope);val c=Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE,key(),GCMParameterSpec(128,bytes.copyOfRange(0,12)));c.updateAAD(origin.toByteArray())
            val plain=c.doFinal(bytes,12,bytes.size-12)
            try {val j=JSONObject(String(plain));CloudSession(UUID.fromString(j.getString("userId")),j.getString("accessToken"),j.getString("refreshToken"),j.getLong("expiresAt"))}
            finally {plain.fill(0)}
        }catch(_:Exception){null}
    }
    fun clear() = synchronized(sessionLock) {check(prefs.edit().remove("session").commit())}
    internal fun replace(previousRefreshToken: String,session: CloudSession): Boolean = synchronized(sessionLock) {
        if(load()?.refreshToken!=previousRefreshToken) false else {save(session);true}
    }
    fun pin(link: JSONObject) {check(prefs.edit().putString("pin:${link.getString("id")}",fingerprints(link)).commit())}
    fun pinned(link: JSONObject)=prefs.getString("pin:${link.getString("id")}",null)==fingerprints(link)
    private fun fingerprints(link: JSONObject)=listOf("ownerDevice","holderDevice").joinToString("/") {
        val d=link.getJSONObject(it);d.getString("id")+":"+d.getString("hpke_fingerprint")+":"+d.getString("signing_fingerprint")
    }
}

class CloudClient(val baseUrl: String,private val publishable: String,val sessions: SessionStore,private val allowLocal: Boolean=BuildConfig.DEBUG) {
    init {validate(baseUrl)}
    private fun validate(url: String) {
        val uri=URI(url)
        require(uri.userInfo==null && uri.fragment==null && (uri.scheme=="https" ||
            (allowLocal && uri.scheme=="http" && uri.host in setOf("10.0.2.2","127.0.0.1","localhost")))) {"BACKEND_URL"}
    }
    private fun sameOrigin(url: String) {
        validate(url);val a=URI(baseUrl);val b=URI(url)
        require(a.scheme==b.scheme&&a.host==b.host&&a.port==b.port) {"SIGNED_URL_ORIGIN"}
    }
    private fun http(url: String,method: String,body: ByteArray?=null,token: String?=null,octets: Boolean=false): ByteArray {
        validate(url)
        val connection=URI(url).toURL().openConnection() as HttpURLConnection
        try {
            connection.requestMethod=method;connection.instanceFollowRedirects=false;connection.connectTimeout=15000;connection.readTimeout=30000
            connection.setRequestProperty("apikey",publishable)
            if(token!=null) connection.setRequestProperty("Authorization","Bearer $token")
            if(body!=null){connection.doOutput=true;connection.setFixedLengthStreamingMode(body.size);connection.setRequestProperty("Content-Type",if(octets)"application/octet-stream" else "application/json")
                if(octets) connection.setRequestProperty("x-upsert","false")
                connection.outputStream.use {it.write(body)}
            }
            val status=connection.responseCode
            val stream=if(status in 200..299) connection.inputStream else connection.errorStream
            val bytes=stream?.use {
                val out=java.io.ByteArrayOutputStream();val buffer=ByteArray(4096)
                while(true){val count=it.read(buffer);if(count<0)break;require(out.size()+count<=1_048_576) {"RESPONSE_TOO_LARGE"};out.write(buffer,0,count)}
                out.toByteArray()
            }?:byteArrayOf()
            if(status !in 200..299){val code=try{val j=JSONObject(String(bytes));j.optJSONObject("error")?.optString("code")?:j.optString("error_code","HTTP_ERROR")}catch(_:Exception){"HTTP_ERROR"}
                throw CloudError(status,code.takeIf {it.matches(Regex("[A-Za-z0-9_]{1,80}"))}?:"HTTP_ERROR")}
            return bytes
        } finally {connection.disconnect()}
    }
    private fun parsedSession(j: JSONObject): CloudSession = CloudSession(UUID.fromString(j.getJSONObject("user").getString("id")),j.getString("access_token"),j.getString("refresh_token"),
        System.currentTimeMillis()+j.optLong("expires_in",3600)*1000)
    private fun session(j: JSONObject)=parsedSession(j).also(sessions::save)
    suspend fun login(email: String,password: String)=withContext(Dispatchers.IO){session(JSONObject(String(http("$baseUrl/auth/v1/token?grant_type=password","POST",JSONObject().put("email",email).put("password",password).toString().toByteArray()))))}
    suspend fun signup(email: String,password: String)=withContext(Dispatchers.IO){
        val j=JSONObject(String(http("$baseUrl/auth/v1/signup","POST",JSONObject().put("email",email).put("password",password).toString().toByteArray())))
        if(j.has("access_token"))session(j) else null
    }
    private fun accessToken(): String = synchronized(SessionStore.refreshLock) {
        val s=sessions.load()?:throw CloudError(401,"AUTH_REQUIRED")
        if(s.expiresAt>System.currentTimeMillis()+30000)return@synchronized s.accessToken
        try {
            val refreshed=parsedSession(JSONObject(String(http("$baseUrl/auth/v1/token?grant_type=refresh_token","POST",JSONObject().put("refresh_token",s.refreshToken).toString().toByteArray()))))
            if(!sessions.replace(s.refreshToken,refreshed))throw CloudError(401,"AUTH_REQUIRED")
            refreshed.accessToken
        }
        catch(e:CloudError){if(e.status in setOf(400,401,403))throw CloudError(401,"AUTH_REQUIRED");throw e}
    }
    suspend fun api(path: String,method: String="GET",body: JSONObject?=null): Any=withContext(Dispatchers.IO){
        JSONObject(String(http("$baseUrl/functions/v1/api$path",method,body?.toString()?.toByteArray(),accessToken()))).get("data")
    }
    suspend fun register(identity: PublicDeviceIdentity) {
        api("/bootstrap","POST",JSONObject().put("displayName","Pengguna uji SwaraLara"))
        api("/devices","POST",JSONObject().put("id",identity.deviceId).put("label","Android SwaraLara")
            .put("hpkePublicKeysetBase64",identity.hpkePublicKeysetBase64).put("signingPublicSpkiBase64",identity.signingPublicSpkiBase64).put("proofSignatureBase64",identity.proofSignatureBase64))
    }
    suspend fun links()=api("/trust") as JSONArray
    suspend fun confirm(link: JSONObject,identity: DeviceIdentity) {
        api("/trust/${UUID.fromString(link.getString("id"))}/confirm","POST",JSONObject().put("deviceId",identity.publicIdentity().deviceId)
            .put("signatureBase64",identity.trustConfirmation(UUID.fromString(link.getString("id")))))
        sessions.pin(link)
    }
    suspend fun sync(snapshot: EncryptedRecordingSnapshot,receipt: suspend (UploadReceipt)->Unit) = withContext(Dispatchers.IO) {
        check(snapshot.policyCode!="demo_2of3" && snapshot.cloudRegistrationJson!=null && snapshot.cloudOwnerUserId==sessions.load()?.userId) {"CLOUD_POLICY_OR_ACCOUNT"}
        api("/recordings","POST",JSONObject(requireNotNull(snapshot.cloudRegistrationJson)))
        for(s in snapshot.segments) {
            require(s.file.length()==s.byteLength && s.byteLength<=384098)
            val bytes=s.file.readBytes();val digest=java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {"%02x".format(it)}
            require(bytes.size.toLong()==s.byteLength && digest==s.objectHash) {"LOCAL_OBJECT_CHANGED"}
            val p=JSONObject().put("index",s.index).put("objectHash",s.objectHash)
            val url=api("/recordings/${snapshot.recordingId}/segments/upload-url","POST",p) as JSONObject
            if(!url.getBoolean("alreadyCommitted")) {
                val signed=url.getString("uploadUrl");sameOrigin(signed)
                try {http(signed,"PUT",bytes,octets=true)}catch(e: CloudError){if(e.status !in setOf(400,409))throw e}
                // An existing object is only accepted after the server reads and validates it at commit.
            }
            val response=api("/recordings/${snapshot.recordingId}/segments/commit","POST",p) as JSONObject
            val accepted=UploadReceipt(UUID.fromString(response.getString("recordingId")),response.getLong("index"),response.getString("objectHash"),response.getLong("committedAtServer"))
            require(accepted.recordingId==snapshot.recordingId && accepted.index==s.index && accepted.objectHash==s.objectHash)
            receipt(accepted)
        }
    }

    // ── M3: Distribusi envelope ──────────────────────────────────────────────
    suspend fun uploadEnvelopes(
        recordingId: UUID,
        envelopes: List<ShareEnvelope>,
    ): List<EnvelopeUploadReceipt> = withContext(Dispatchers.IO) {
        val arr = org.json.JSONArray()
        envelopes.forEach { e -> arr.put(JSONObject(M3Json.envelope(e))) }
        val resp = api("/recordings/$recordingId/share-envelopes", "POST",
            JSONObject().put("envelopes", arr)) as org.json.JSONArray
        (0 until resp.length()).map { i ->
            val o = resp.getJSONObject(i)
            EnvelopeUploadReceipt(
                UUID.fromString(o.getString("recordingId")),
                o.getInt("shareIndex"),
                o.getString("ciphertextHash"),
                o.getLong("receivedAtServer"),
            )
        }
    }

    suspend fun getMyShare(recordingId: UUID): Pair<SignedPolicyPackage, ShareEnvelope>? =
        withContext(Dispatchers.IO) {
            try {
                val o = api("/recordings/$recordingId/my-share") as JSONObject
                val policy = SignedPolicyPackage(
                    o.getJSONObject("policy").getString("snapshotBase64"),
                    o.getJSONObject("policy").getString("signatureBase64"),
                )
                val env = M3Json.envelope(o.getJSONObject("envelope").toString())
                Pair(policy, env)
            } catch (e: CloudError) {
                if (e.status == 404) null else throw e
            }
        }

    suspend fun ackShare(
        recordingId: UUID,
        ack: DeviceSignedAction,
    ): Unit = withContext(Dispatchers.IO) {
        api("/recordings/$recordingId/my-share/ack", "POST",
            JSONObject(M3Json.action(ack)))
        Unit
    }

    // ── M3: Access requests ──────────────────────────────────────────────────
    suspend fun createAccessRequest(request: KeyAccessRequest): UUID =
        withContext(Dispatchers.IO) {
            val o = api("/access-requests", "POST",
                JSONObject(M3Json.request(request))) as JSONObject
            UUID.fromString(o.getString("requestId"))
        }

    suspend fun getAccessRequests(): List<KeyAccessRequest> =
        withContext(Dispatchers.IO) {
            val arr = api("/access-requests") as org.json.JSONArray
            (0 until arr.length()).map { i -> M3Json.request(arr.getJSONObject(i).toString()) }
        }

    suspend fun approveRelease(
        requestId: UUID,
        release: ShareRelease,
    ): Unit = withContext(Dispatchers.IO) {
        api("/access-requests/$requestId/decision", "POST",
            JSONObject().put("approved", true).put("release", JSONObject(M3Json.release(release))))
        Unit
    }

    /** Send the signed decision fields required by the Edge API. */
    suspend fun submitDecision(request: KeyAccessRequest, identity: DeviceIdentity, release: ShareRelease?) {
        val deviceId = identity.publicIdentity().deviceId
        val snapshot = java.nio.ByteBuffer.wrap(decodeBase64(request.policy.snapshotBase64))
        require(snapshot.remaining() in setOf(248, 345) && snapshot.int == 0x53575031)
        snapshot.position(53)
        val count = snapshot.get().toInt()
        require(count in 2..3 && snapshot.remaining() == count * 97)
        var ownIndex: Int? = null
        repeat(count) {
            val index = snapshot.get().toInt()
            snapshot.position(snapshot.position() + 16)
            val memberDevice = UUID(snapshot.long, snapshot.long)
            snapshot.position(snapshot.position() + 64)
            if (memberDevice == deviceId) ownIndex = index
        }
        val index = requireNotNull(ownIndex) { "DEVICE_NOT_IN_POLICY" }
        require(release == null || (release.requestId == request.requestId &&
            release.recordingId == request.recordingId && release.holderDeviceId == deviceId && release.shareIndex == index))
        val decision = if (release == null) "deny" else "approve"
        val bytes = "$decision:${request.requestId}:$index".toByteArray(Charsets.UTF_8)
        val payload = JSONObject().put("decision", decision).put("holderDeviceId", deviceId)
            .put("shareIndex", index).put("signedDecisionBase64", encodeBase64(bytes))
            .put("decisionSignatureBase64", encodeBase64(identity.sign(bytes)))
        release?.let {
            payload.put("releaseCiphertextBase64", it.ciphertextBase64)
                .put("contextBytesBase64", it.contextBase64)
                .put("holderSignatureBase64", it.holderSignatureBase64)
                .put("ciphertextSha256", it.ciphertextHash)
        }
        api("/access-requests/${request.requestId}/decision", "POST", payload)
    }

    suspend fun getReleases(
        requestId: UUID,
        auth: DeviceSignedAction,
    ): List<ShareRelease> = withContext(Dispatchers.IO) {
        val arr = api("/access-requests/$requestId/releases?auth=${java.net.URLEncoder.encode(M3Json.action(auth), "UTF-8")}") as org.json.JSONArray
        (0 until arr.length()).map { i -> M3Json.release(arr.getJSONObject(i).toString()) }
    }

    suspend fun cancelRequest(
        requestId: UUID,
        cancel: DeviceSignedAction,
    ): Unit = withContext(Dispatchers.IO) {
        api("/access-requests/$requestId/cancel", "POST",
            JSONObject(M3Json.action(cancel)))
        Unit
    }
}
