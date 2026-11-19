package id.swaralara.app

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import id.swaralara.app.backend.*
import id.swaralara.core.*
import java.io.File
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Real Tink/Keystore, three isolated identities, production Android HTTP client and production
 * Edge/SQL. Credentials select either the local fixture or temporary hosted Supabase accounts.
 * Three isolated identities run on one physical phone.
 */
@RunWith(AndroidJUnit4::class)
class M3TransportIntegrationTest {
    private data class Actor(
        val namespace: String,
        val client: CloudClient,
        val identity: DeviceIdentity,
        val vault: LocalVault,
        val exchange: SecureKeyExchange,
        val db: LocalDatabase,
        val store: SessionStore,
        val userId: UUID,
    )

    private val actors = mutableListOf<Actor>()
    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val args
        get() = InstrumentationRegistry.getArguments()

    private suspend fun actor(email: String): Actor {
        val namespace = "m3t-${UUID.randomUUID()}"
        val origin = args.getString("fixtureOrigin") ?: "http://127.0.0.1:8787"
        val store = SessionStore(context, origin, namespace)
        val client =
            CloudClient(
                origin,
                requireNotNull(args.getString("fixturePublishableKey")),
                store,
                true,
            )
        val session = client.login(email, requireNotNull(args.getString("fixturePassword")))
        val protector = KeyProtector()
        val identity = DeviceIdentity(context, protector, namespace)
        val db = Room.databaseBuilder(context, LocalDatabase::class.java, "$namespace.db").build()
        val vault = LocalVault(File(context.filesDir, namespace), db, protector, identity)
        val exchange = LocalKeyExchange(db, vault, identity)
        client.register(identity.publicIdentity())
        return Actor(namespace, client, identity, vault, exchange, db, store, session.userId)
            .also(actors::add)
    }

    private suspend fun pair(owner: Actor, holder: Actor) {
        val invitation =
            owner.client.api(
                "/trust/invitations",
                "POST",
                JSONObject().put("deviceId", owner.identity.publicIdentity().deviceId),
            ) as JSONObject
        holder.client.api(
            "/trust/accept",
            "POST",
            JSONObject()
                .put("token", invitation.getString("token"))
                .put("deviceId", holder.identity.publicIdentity().deviceId),
        )
        val rows = owner.client.links()
        val link =
            (0 until rows.length()).map(rows::getJSONObject).single {
                it.getString("holder_device_id") ==
                    holder.identity.publicIdentity().deviceId.toString()
            }
        owner.client.confirm(link, owner.identity, owner.exchange)
        holder.client.confirm(link, holder.identity, holder.exchange)
    }

    private suspend fun recording(owner: Actor, peers: List<Actor>, policyCode: String): UUID {
        val members =
            peers.mapIndexed { index, actor ->
                val d = actor.identity.publicIdentity()
                CloudMember(
                    index + 1,
                    actor.userId,
                    d.deviceId,
                    d.hpkeFingerprint,
                    d.signingFingerprint,
                )
            }
        val config =
            CaptureConfig(
                "retrospective",
                CloudCapturePolicy(
                    owner.userId,
                    owner.identity.publicIdentity().deviceId,
                    policyCode,
                    members,
                ),
            )
        val id = UUID.randomUUID()
        val session = owner.vault.create(id, config, 16000)
        // Synthetic PCM, never captures the user's microphone or writes clear audio to disk.
        try {
            owner.vault.persist(id, session.encrypt(ByteArray(8000)))
        } finally {
            session.close()
        }
        owner.vault.capture(id, CaptureState.SEALED)
        owner.client.sync(owner.vault.exportEncryptedSnapshot(id), owner.vault::acknowledgeUpload)
        val policy = owner.exchange.exportPolicy(id)
        for (peer in peers) peer.exchange.acceptPolicyDevices(policy, peer.client.policyDevices(id))
        val envelopes = owner.exchange.prepareDistribution(id)
        val first = owner.client.uploadEnvelopes(id, envelopes)
        val retry = owner.client.uploadEnvelopes(id, envelopes)
        assertEquals(first, retry)
        first.forEach { owner.exchange.acknowledgeEnvelopeUpload(it) }
        for (peer in peers) M3Sync.refresh(peer.identity, peer.vault, peer.exchange, peer.client)
        M3Sync.refresh(owner.identity, owner.vault, owner.exchange, owner.client)
        assertEquals(
            RecoveryState.HOLDERS_ACKNOWLEDGED,
            owner.vault.observeRecordings().first().single { it.id == id }.recovery,
        )
        return id
    }

    private suspend fun approve(actor: Actor, request: KeyAccessRequest) {
        val inbox = actor.client.getAccessRequests(actor.identity.publicIdentity().deviceId)
        val wire = inbox.single { it.requestId == request.requestId }
        val release = actor.exchange.approveAndRelease(wire, userApproved = true)
        actor.client.submitDecision(wire, actor.identity, release)
        // Lost-response retry must return the persisted decision, not count this holder twice.
        actor.client.submitDecision(wire, actor.identity, release)
    }

    @Test
    fun ownerRequiredAndTwoOfThreeRecoverOverProductionTransport() = runBlocking {
        try {
            val owner = actor(args.getString("ownerEmail") ?: "owner@test.local")
            val a = actor(args.getString("holderEmail") ?: "holder@test.local")
            val b = actor(args.getString("otherEmail") ?: "outsider@test.local")
            pair(owner, a)
            pair(owner, b)
            val two = recording(owner, listOf(owner, a), "owner_required_2of2")
            owner.exchange.retireLocalKey(two, true)
            assertFalse(owner.vault.inspect(two).passed)
            val request = owner.exchange.createRequest(owner.exchange.exportPolicy(two))
            assertEquals(request, LocalKeyExchange(owner.db,owner.vault,owner.identity).pendingRequests().single {it.requestId==request.requestId})
            assertEquals(request.requestId, owner.client.createAccessRequest(request))
            assertEquals(request.requestId, owner.client.createAccessRequest(request))
            approve(a, request)
            M3Sync.refresh(owner.identity, owner.vault, owner.exchange, owner.client)
            assertEquals(
                "pending",
                owner.client.requestDetail(request.requestId).getString("state"),
            )
            approve(owner, request)
            assertEquals("ready", owner.client.requestDetail(request.requestId).getString("state"))
            val auth = owner.exchange.authorizeReleasesRead(request.requestId)
            assertTrue(
                owner.exchange
                    .recover(request.requestId, owner.client.getReleases(request.requestId, auth))
                    .passed
            )
            assertTrue(owner.vault.inspect(two).passed)
            owner.exchange.closeRecovery(request.requestId)
            assertFalse(owner.vault.inspect(two).passed)

            val three = recording(owner, listOf(owner, a, b), "recovery_2of3")
            val policy = owner.exchange.exportPolicy(three)
            val recover = a.exchange.createRequest(policy)
            a.client.createAccessRequest(recover)
            approve(a, recover)
            approve(b, recover) // No owner's release for a 2-of-3 policy.
            val read = a.exchange.authorizeReleasesRead(recover.requestId)
            a.client.downloadForRecovery(a.vault, a.exchange, recover.requestId, read)
            assertFalse(a.vault.inspect(three).passed)
            assertTrue(
                a.exchange
                    .recover(recover.requestId, a.client.getReleases(recover.requestId, read))
                    .passed
            )
            assertEquals(4000L, a.vault.inspect(three).frames)
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            val playback = LocalPlayback(a.vault, scope, CompletableDeferred(Unit)) { true }
            try {
                assertTrue(playback.prepare(three))
                playback.play()
                val terminal =
                    withTimeoutOrNull(10000) {
                        playback.state.first {
                            it.phase in setOf(PlaybackPhase.COMPLETED, PlaybackPhase.FAILED)
                        }
                    }
                assertNotNull("Playback stalled: ${playback.state.value}", terminal)
                assertEquals(PlaybackPhase.COMPLETED, playback.state.value.phase)
            } finally {
                playback.release()
                scope.cancel()
            }

            val cancelled = a.exchange.createRequest(policy)
            a.client.createAccessRequest(cancelled)
            val cancel = a.exchange.cancelRequest(cancelled.requestId)
            M3Sync.refresh(a.identity,a.vault,a.exchange,a.client)
            a.client.cancelRequest(
                cancelled.requestId,
                a.exchange.cancelRequest(cancelled.requestId),
            )
            val detail = b.client.requestDetail(cancelled.requestId)
            assertEquals("cancelled", detail.getString("state"))
            assertEquals(cancel.payloadBase64,detail.getJSONObject("cancellation").getString("payloadBase64"))
            M3Sync.refresh(b.identity,b.vault,b.exchange,b.client)
            try {
                b.exchange.approveAndRelease(cancelled, true)
                fail("Cancelled request released a share")
            } catch (_: IllegalArgumentException) {}
        } finally {
            for (actor in actors) {
                actor.exchange.closeOpenSessions()
                actor.exchange.pendingRequests().forEach {
                    actor.exchange.closeRecovery(it.requestId)
                }
                actor.vault.observeRecordings().first().forEach {
                    KeyProtector.destroyRecordingKey(it.id)
                }
                actor.store.clear()
                actor.db.close()
                context.deleteDatabase("${actor.namespace}.db")
                context.deleteSharedPreferences("swl-device-${actor.namespace}")
                context.deleteSharedPreferences("swl-session-${actor.namespace}")
                java.security.KeyStore.getInstance("AndroidKeyStore")
                    .apply { load(null) }
                    .deleteEntry("swaralara.signing.${actor.namespace}")
                val directory = File(context.filesDir, actor.namespace)
                check(
                    directory.canonicalFile.parentFile == context.filesDir.canonicalFile &&
                        directory.name.startsWith("m3t-")
                )
                directory.deleteRecursively()
            }
        }
    }
}
