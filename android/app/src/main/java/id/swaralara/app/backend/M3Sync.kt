package id.swaralara.app.backend

import id.swaralara.core.*
import java.time.Instant
import java.util.UUID
import kotlinx.coroutines.flow.first
import org.json.JSONObject

object M3Sync {
    suspend fun refresh(core: CoreRuntime, client: CloudClient): List<JSONObject> {
        core.awaitReady()
        return refresh(core.identity, core.vault, core.keyExchange, client)
    }

    suspend fun refresh(
        identity: DeviceIdentity,
        vault: SecureVault,
        exchange: SecureKeyExchange,
        client: CloudClient,
    ): List<JSONObject> {
        client.pinConfirmedLinks(exchange)
        val own = identity.publicIdentity().deviceId
        for ((id, action) in exchange.outgoingCancellations()) {
            try {
                client.cancelRequest(id, action)
            } catch (e: CloudError) {
                if (e.status !in setOf(404, 410)) throw e
            }
        }
        val records = client.m3Recordings(own)
        for (record in records) {
            val id = UUID.fromString(record.getString("id"))
            val policy = M3TransportCodec.policy(record)
            exchange.acceptPolicyDevices(policy, client.policyDevices(id))
            val envelope = client.getMyShare(id, exchange.authorizeShareRead(policy))
            if (envelope != null) {
                val ack = exchange.receiveShare(envelope.first, envelope.second)
                client.ackShare(id, ack)
            }
            if (
                record.getString("sourceDeviceId") == own.toString() &&
                    vault.observeRecordings().first().any {
                        it.id == id &&
                            it.recovery in
                                setOf(
                                    RecoveryState.ENVELOPES_UPLOADED,
                                    RecoveryState.HOLDERS_ACKNOWLEDGED,
                                )
                    }
            ) {
                for (ack in client.acknowledgments(id)) {
                    // Expired, previously unseen acknowledgments must be renewed by their holder.
                    if (M3TransportCodec.actionExpiresAt(ack) > System.currentTimeMillis())
                        exchange.acceptAcknowledgment(id, ack)
                }
            }
        }
        for (row in client.requestRows()) {
            if (
                row.getString("state") == "cancelled" &&
                    Instant.parse(row.getString("expiresAt")).toEpochMilli() >
                        System.currentTimeMillis()
            ) {
                val detail = client.requestDetail(UUID.fromString(row.getString("id")))
                val cancellation = detail.optJSONObject("cancellation") ?: continue
                exchange.receiveCancellation(
                    M3TransportCodec.request(detail),
                    M3Json.action(cancellation.toString()),
                )
            }
        }
        exchange.pendingRequests()
        return records
    }
}
