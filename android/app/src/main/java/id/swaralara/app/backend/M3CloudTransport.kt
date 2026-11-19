package id.swaralara.app.backend

import id.swaralara.core.*
import java.net.URLEncoder
import java.util.UUID
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import org.json.JSONArray
import org.json.JSONObject

suspend fun CloudClient.pinConfirmedLinks(core: CoreRuntime) {
    pinConfirmedLinks(core.keyExchange)
}

suspend fun CloudClient.pinConfirmedLinks(exchange: SecureKeyExchange) {
    val rows = links()
    for (i in 0 until rows.length()) {
        val link = rows.getJSONObject(i)
        if (!sessions.pinned(link) || link.getString("state") != "active") continue
        for (role in listOf("ownerDevice", "holderDevice")) {
            val peer = link.getJSONObject(role)
            exchange.pinTrustedDevice(
                UUID.fromString(peer.getString("userId")),
                M3TransportCodec.publicDevice(peer),
                peer.getString("hpke_fingerprint"),
                peer.getString("signing_fingerprint"),
            )
        }
    }
}

suspend fun CloudClient.m3Recordings(deviceId: UUID): List<JSONObject> {
    val rows = api("/m3/recordings?deviceId=$deviceId") as JSONArray
    return (0 until rows.length()).map(rows::getJSONObject)
}

suspend fun CloudClient.policyDevices(id: UUID): List<PublicDeviceIdentity> {
    val rows = api("/recordings/$id/members") as JSONArray
    return (0 until rows.length()).map { M3TransportCodec.publicDevice(rows.getJSONObject(it)) }
}

suspend fun CloudClient.uploadEnvelopes(
    recordingId: UUID,
    envelopes: List<ShareEnvelope>,
): List<EnvelopeUploadReceipt> {
    val payload = JSONArray()
    envelopes.forEach { payload.put(M3TransportCodec.envelope(it)) }
    val response =
        api(
            "/recordings/$recordingId/share-envelopes",
            "POST",
            JSONObject().put("envelopes", payload),
        )
            as JSONObject
    val rows = response.getJSONArray("receipts")
    return (0 until rows.length())
        .map { i ->
            val row = rows.getJSONObject(i)
            EnvelopeUploadReceipt(
                UUID.fromString(row.getString("recordingId")),
                row.getInt("shareIndex"),
                row.getString("ciphertextHash"),
                row.getLong("receivedAtServer"),
            )
        }
        .also { receipts ->
            require(
                receipts.size == envelopes.size &&
                    receipts.map { it.shareIndex }.distinct().size == envelopes.size
            )
            receipts.forEach { r ->
                require(
                    r.recordingId == recordingId &&
                        envelopes.single { it.shareIndex == r.shareIndex }.ciphertextHash ==
                            r.ciphertextHash
                )
            }
        }
}

internal fun actionQuery(a: DeviceSignedAction) =
    "deviceId=${M3TransportCodec.actionDevice(a)}&actionBase64=${URLEncoder.encode(a.payloadBase64,"UTF-8")}&signatureBase64=${URLEncoder.encode(a.signatureBase64,"UTF-8")}"

suspend fun CloudClient.getMyShare(
    recordingId: UUID,
    auth: DeviceSignedAction,
): Pair<SignedPolicyPackage, ShareEnvelope>? {
    return try {
        val row = api("/recordings/$recordingId/my-share?${actionQuery(auth)}") as JSONObject
        M3TransportCodec.policy(row) to M3TransportCodec.envelope(row)
    } catch (e: CloudError) {
        if (e.status == 404) null else throw e
    }
}

suspend fun CloudClient.ackShare(recordingId: UUID, ack: DeviceSignedAction) {
    api("/recordings/$recordingId/my-share/ack", "POST", M3TransportCodec.action(ack))
}

suspend fun CloudClient.acknowledgments(recordingId: UUID): List<DeviceSignedAction> {
    val rows = api("/recordings/$recordingId/acknowledgments") as JSONArray
    return (0 until rows.length()).map { M3Json.action(rows.getJSONObject(it).toString()) }
}

suspend fun CloudClient.createAccessRequest(request: KeyAccessRequest): UUID {
    val row = api("/access-requests", "POST", M3TransportCodec.request(request)) as JSONObject
    return UUID.fromString(row.getString("id")).also { require(it == request.requestId) }
}

suspend fun CloudClient.requestRows(): List<JSONObject> {
    val rows = api("/access-requests") as JSONArray
    return (0 until rows.length()).map(rows::getJSONObject)
}

suspend fun CloudClient.requestDetail(id: UUID) = api("/access-requests/$id") as JSONObject

suspend fun CloudClient.getAccessRequests(deviceId: UUID? = null): List<KeyAccessRequest> {
    val result = mutableListOf<KeyAccessRequest>()
    for (row in requestRows()) {
        if (row.getString("state") != "pending") continue
        val detail = requestDetail(UUID.fromString(row.getString("id")))
        if (detail.getString("state") != "pending") continue
        val decisions = detail.getJSONArray("decisions")
        if (
            deviceId != null &&
                (0 until decisions.length()).any {
                    decisions.getJSONObject(it).getString("holder_device_id") == deviceId.toString()
                }
        )
            continue
        val request = M3TransportCodec.request(detail)
        if (
            deviceId == null ||
                M3TransportCodec.members(request.policy).any { it.deviceId == deviceId }
        )
            result.add(request)
    }
    return result
}

suspend fun CloudClient.submitDecision(
    request: KeyAccessRequest,
    identity: DeviceIdentity,
    release: ShareRelease?,
) {
    val device = identity.publicIdentity().deviceId
    val member = M3TransportCodec.members(request.policy).single { it.deviceId == device }
    require(
        release == null ||
            (release.requestId == request.requestId &&
                release.recordingId == request.recordingId &&
                release.holderDeviceId == device &&
                release.shareIndex == member.shareIndex)
    )
    val decision = if (release == null) "deny" else "approve"
    val signed = "$decision:${request.requestId}:${member.shareIndex}".toByteArray(Charsets.UTF_8)
    val payload =
        JSONObject()
            .put("decision", decision)
            .put("holderDeviceId", device)
            .put("shareIndex", member.shareIndex)
            .put("signedDecisionBase64", encodeBase64(signed))
            .put("decisionSignatureBase64", encodeBase64(identity.sign(signed)))
    release?.let {
        payload
            .put("releaseCiphertextBase64", it.ciphertextBase64)
            .put("contextBytesBase64", it.contextBase64)
            .put("holderSignatureBase64", it.holderSignatureBase64)
            .put("ciphertextSha256", it.ciphertextHash)
    }
    api("/access-requests/${request.requestId}/decision", "POST", payload)
}

suspend fun CloudClient.getReleases(requestId: UUID, auth: DeviceSignedAction): List<ShareRelease> {
    val request = M3TransportCodec.request(requestDetail(requestId))
    val rows = api("/access-requests/$requestId/releases?${actionQuery(auth)}") as JSONArray
    return (0 until rows.length()).map { M3TransportCodec.release(rows.getJSONObject(it), request) }
}

suspend fun CloudClient.cancelRequest(requestId: UUID, cancel: DeviceSignedAction) {
    api("/access-requests/$requestId/cancel", "POST", M3TransportCodec.action(cancel))
}

suspend fun CloudClient.downloadForRecovery(
    core: CoreRuntime,
    requestId: UUID,
    auth: DeviceSignedAction,
) {
    downloadForRecovery(core.vault, core.keyExchange, requestId, auth)
}

suspend fun CloudClient.downloadForRecovery(
    vault: SecureVault,
    exchange: SecureKeyExchange,
    requestId: UUID,
    auth: DeviceSignedAction,
) {
    val meta = api("/access-requests/$requestId/recording?${actionQuery(auth)}") as JSONObject
    val packet = M3TransportCodec.policy(meta)
    val id = M3TransportCodec.recordingId(packet)
    if (vault.observeRecordings().first().any { it.id == id && it.sync == SyncState.SYNCED }) return
    exchange.acceptPolicyDevices(packet, policyDevices(id))
    val descriptor =
        RemoteRecordingPackage(
            packet,
            meta.getString("kind"),
            meta.getLong("startedAtDevice"),
            meta.getInt("sampleRate"),
            meta.getLong("totalSamples"),
            meta.getInt("totalSegments"),
            CaptureState.valueOf(meta.getString("captureState").uppercase()),
        )
    vault.importEncryptedRecording(
        descriptor,
        flow {
            var offset = 0
            while (offset < descriptor.segmentCount) {
                val rows =
                    api("/access-requests/$requestId/segments?offset=$offset&${actionQuery(auth)}")
                        as JSONArray
                require(
                    rows.length() in 1..50 && offset + rows.length() <= descriptor.segmentCount
                ) {
                    "INCOMPLETE_DOWNLOAD"
                }
                for (i in 0 until rows.length()) {
                    val row = rows.getJSONObject(i)
                    require(row.getLong("index") == offset.toLong() + i)
                    val bytes = encryptedObject(row.getString("readUrl"))
                    val digest =
                        java.security.MessageDigest.getInstance("SHA-256")
                            .digest(bytes)
                            .joinToString("") { "%02x".format(it) }
                    require(
                        bytes.size == row.getInt("byteLength") &&
                            digest == row.getString("objectHash")
                    ) {
                        "OBJECT_HASH"
                    }
                    emit(bytes)
                }
                offset += rows.length()
            }
        },
    )
}
