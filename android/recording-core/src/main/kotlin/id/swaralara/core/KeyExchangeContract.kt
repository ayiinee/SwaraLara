package id.swaralara.core

import java.util.UUID

/**
 * Public metadata/ciphertext only. No private key, DEK, or plaintext share is returned by this
 * facade.
 */
data class SignedPolicyPackage(val snapshotBase64: String, val signatureBase64: String)

data class ShareEnvelope(
    val recordingId: UUID,
    val policyHash: String,
    val shareIndex: Int,
    val holderDeviceId: UUID,
    val ciphertextBase64: String,
    val contextBase64: String,
    val ciphertextHash: String,
    val ownerSignatureBase64: String,
    val schemeVersion: String = "shamir-bc-gf256-v1",
)

data class DeviceSignedAction(val payloadBase64: String, val signatureBase64: String)

data class EnvelopeUploadReceipt(
    val recordingId: UUID,
    val shareIndex: Int,
    val ciphertextHash: String,
    val receivedAtServer: Long,
)

data class KeyAccessRequest(
    val requestId: UUID,
    val recordingId: UUID,
    val requesterDeviceId: UUID,
    val policy: SignedPolicyPackage,
    val publicKeysetBase64: String,
    val issuedAt: Long,
    val expiresAt: Long,
    val nonce: UUID,
    val signatureBase64: String,
)

data class ShareRelease(
    val requestId: UUID,
    val recordingId: UUID,
    val shareIndex: Int,
    val holderDeviceId: UUID,
    val issuedAt: Long,
    val nonce: UUID,
    val ciphertextBase64: String,
    val contextBase64: String,
    val ciphertextHash: String,
    val holderSignatureBase64: String,
)

data class KeyRecoveryResult(val passed: Boolean, val code: String, val message: String)

interface SecureKeyExchange {
    suspend fun pinTrustedDevice(
        userId: UUID,
        device: PublicDeviceIdentity,
        expectedHpkeFingerprint: String,
        expectedSigningFingerprint: String,
    )

    suspend fun exportPolicy(recordingId: UUID): SignedPolicyPackage

    /** Roster is authenticated by the already pinned owner's signed policy; every identity must prove its key. */
    suspend fun acceptPolicyDevices(policy: SignedPolicyPackage, devices: List<PublicDeviceIdentity>)

    suspend fun pendingRequests(): List<KeyAccessRequest>

    suspend fun outgoingCancellations(): List<Pair<UUID, DeviceSignedAction>>

    suspend fun prepareDistribution(recordingId: UUID): List<ShareEnvelope>

    suspend fun receiveShare(
        policy: SignedPolicyPackage,
        envelope: ShareEnvelope,
    ): DeviceSignedAction

    suspend fun authorizeShareRead(policy: SignedPolicyPackage): DeviceSignedAction

    suspend fun acknowledgeEnvelopeUpload(receipt: EnvelopeUploadReceipt)

    suspend fun acceptAcknowledgment(recordingId: UUID, acknowledgment: DeviceSignedAction)

    /**
     * Caller must have explained threshold-only access and obtained the user's explicit consent.
     */
    suspend fun retireLocalKey(recordingId: UUID, thresholdOnlyConsent: Boolean)

    suspend fun createRequest(
        policy: SignedPolicyPackage,
        lifetimeMillis: Long = 900_000,
    ): KeyAccessRequest

    suspend fun authorizeReleasesRead(requestId: UUID): DeviceSignedAction

    /** Only call from an explicit approval action; never automatically approve notifications. */
    suspend fun approveAndRelease(request: KeyAccessRequest, userApproved: Boolean): ShareRelease

    suspend fun recover(requestId: UUID, releases: List<ShareRelease>): KeyRecoveryResult

    suspend fun cancelRequest(requestId: UUID): DeviceSignedAction

    suspend fun receiveCancellation(request: KeyAccessRequest, cancellation: DeviceSignedAction)

    suspend fun closeRecovery(requestId: UUID)

    suspend fun closeOpenSessions()
}
