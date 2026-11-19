import test from "node:assert/strict";
import { describe, it } from "node:test";
import { randomBytes } from "node:crypto";
import {
  b64,
  bytesHex,
  encodeLp,
  sha,
  trustProof,
  uuidBytes,
} from "../functions/api/protocol.ts";
import { encryptedObjects, seedThroughApi } from "./fixtures.ts";
import { database, ports } from "./harness.ts";

describe("M3 Edge API: share envelopes, acknowledgment, and threshold access requests", () => {
  it("manages share envelope distribution, holder ack, access requests, and release decisions", async (t) => {
    const db = await database();
    t.after(() => db.close());
    const harness = ports(db);

    const { owner, holder, other } = await seedThroughApi(db, harness);

    // Link owner and other (holder2) as well
    const inv2 = await harness.request(
      owner.userId,
      "/trust/invitations",
      "POST",
      { deviceId: owner.id },
    );
    const acc2 = await harness.request(other.userId, "/trust/accept", "POST", {
      deviceId: other.id,
      token: inv2.data.token,
    });
    for (const d of [owner, other]) {
      const r = await harness.request(
        d.userId,
        `/trust/${acc2.data.id}/confirm`,
        "POST",
        {
          deviceId: d.id,
          signatureBase64: d.signature(trustProof(acc2.data.id, d.id)),
        },
      );
      test.equal(r.status, 200);
    }

    // Register 2-of-3 recovery recording
    const recId = crypto.randomUUID();
    const members = [owner, holder, other].map((d, i) => ({
      shareIndex: i + 1,
      userId: d.userId,
      deviceId: d.id,
      hpkeFingerprint: d.hpkeFingerprint,
      signingFingerprint: d.signingFingerprint,
    }));
    const policySnapshot = Buffer.concat([
      Buffer.from("SWP1", "ascii"),
      Buffer.from(recId.replaceAll("-", ""), "hex"),
      Buffer.from(owner.userId.replaceAll("-", ""), "hex"),
      Buffer.from(owner.id.replaceAll("-", ""), "hex"),
      Buffer.from([2, 3]), // recovery_2of3, 3 members
      ...members.map((m) =>
        Buffer.concat([
          Buffer.from([m.shareIndex]),
          Buffer.from(m.userId.replaceAll("-", ""), "hex"),
          Buffer.from(m.deviceId.replaceAll("-", ""), "hex"),
          Buffer.from(m.hpkeFingerprint, "hex"),
          Buffer.from(m.signingFingerprint, "hex"),
        ])
      ),
    ]);
    const policyHash = await sha(new Uint8Array(policySnapshot));
    async function signedQuery(
      action: string,
      resource: string,
      objectHash: string,
      expiresAt: number,
    ) {
      const long = (n: number) => {
        const b = Buffer.alloc(8);
        b.writeBigInt64BE(BigInt(n));
        return b;
      };
      const bytes = encodeLp(
        "swaralara/device-action/v1",
        Buffer.from(action),
        uuidBytes(recId),
        uuidBytes(resource),
        uuidBytes(holder.id),
        bytesHex(policyHash),
        bytesHex(objectHash),
        long(Date.now()),
        long(expiresAt),
        uuidBytes(crypto.randomUUID()),
      );
      return new URLSearchParams({
        deviceId: holder.id,
        actionBase64: b64(bytes),
        signatureBase64: holder.signature(bytes),
      }).toString();
    }

    const reg = {
      id: recId,
      sourceDeviceId: owner.id,
      kind: "retrospective",
      policyCode: "recovery_2of3",
      sampleRate: 16000,
      channels: 1,
      pcmEncoding: "pcm16le",
      startedAtDevice: "2026-11-18T00:00:00Z",
      captureState: "sealed",
      totalSegments: 2,
      totalSamples: 11,
      policySnapshotBase64: b64(policySnapshot),
      policySignatureBase64: owner.signature(policySnapshot),
    };
    const regRes = await harness.request(
      owner.userId,
      "/recordings",
      "POST",
      reg,
    );
    test.equal(regRes.status, 200);

    // Commit audio segments to sync recording
    const segments = encryptedObjects(recId);
    for (const s of segments) {
      harness.objects.set(s.storagePath, s.bytes);
      await harness.request(
        owner.userId,
        `/recordings/${recId}/segments/commit`,
        "POST",
        {
          index: s.index,
          objectHash: s.objectHash,
        },
      );
    }

    // 1. POST /recordings/:id/share-envelopes
    const intBytes = (n: number) => {
      const b = Buffer.alloc(4);
      b.writeUInt32BE(n);
      return b;
    };
    const envelopes = await Promise.all(members.map(async (m) => {
      const cipher = randomBytes(128);
      const cipherSha = await sha(new Uint8Array(cipher));
      const ctx = encodeLp(
        "swaralara/share-envelope/v1",
        uuidBytes(recId),
        bytesHex(policyHash),
        new Uint8Array(intBytes(m.shareIndex)),
        uuidBytes(m.deviceId),
      );
      const sigPayload = encodeLp(
        "swaralara/share-envelope-signature/v1",
        ctx,
        bytesHex(cipherSha),
      );
      return {
        shareIndex: m.shareIndex,
        holderDeviceId: m.deviceId,
        schemeVersion: "shamir-bc-gf256-v1",
        envelopeCiphertextBase64: b64(cipher),
        contextBytesBase64: b64(ctx),
        ownerSignatureBase64: owner.signature(sigPayload),
        ciphertextSha256: cipherSha,
      };
    }));

    const envRes = await harness.request(
      owner.userId,
      `/recordings/${recId}/share-envelopes`,
      "POST",
      { envelopes },
    );
    test.equal(envRes.status, 200);
    test.equal(envRes.data.uploadedCount, 3);

    // Check detail shows recovery_state = 'envelopes_uploaded'
    const detailAfterEnv = await harness.request(
      owner.userId,
      `/recordings/${recId}`,
    );
    test.equal(detailAfterEnv.data.recovery_state, "envelopes_uploaded");

    // 2. GET /recordings/:id/my-share for holder
    const myShare1 = await harness.request(
      holder.userId,
      `/recordings/${recId}/my-share?${await signedQuery(
        "my_share",
        recId,
        policyHash,
        Date.now() + 60000,
      )}`,
    );
    test.equal(myShare1.status, 200);
    test.equal(myShare1.data.shareIndex, 2);
    test.equal(myShare1.data.holderDeviceId, holder.id);

    // 3. POST /recordings/:id/my-share/ack for all members
    const now = Date.now();
    for (
      const [mem, env] of [
        [owner, envelopes[0]],
        [holder, envelopes[1]],
        [other, envelopes[2]],
      ] as const
    ) {
      const timeLong = (t: number) => {
        const b = Buffer.alloc(8);
        b.writeBigInt64BE(BigInt(t));
        return b;
      };
      const actionPayload = encodeLp(
        "swaralara/device-action/v1",
        new TextEncoder().encode("share_ack"),
        uuidBytes(recId),
        uuidBytes(recId),
        uuidBytes(mem.id),
        bytesHex(policyHash),
        bytesHex(env.ciphertextSha256),
        new Uint8Array(timeLong(now)),
        new Uint8Array(timeLong(now + 60000)),
        uuidBytes(crypto.randomUUID()),
      );
      const ackRes = await harness.request(
        mem.userId,
        `/recordings/${recId}/my-share/ack`,
        "POST",
        {
          deviceId: mem.id,
          actionBytesBase64: b64(actionPayload),
          signatureBase64: mem.signature(actionPayload),
        },
      );
      test.equal(ackRes.status, 200);
    }

    const detailAfterAck = await harness.request(
      owner.userId,
      `/recordings/${recId}`,
    );
    test.equal(detailAfterAck.data.recovery_state, "holders_acknowledged");

    // 4. POST /access-requests by holder (to recover recording)
    const reqId = crypto.randomUUID();
    const reqHpkePublic = Buffer.from(
      holder.data.hpkePublicKeysetBase64,
      "base64",
    );
    const reqHpkeSha = await sha(new Uint8Array(reqHpkePublic));
    const timeLong = (t: number) => {
      const b = Buffer.alloc(8);
      b.writeBigInt64BE(BigInt(t));
      return b;
    };
    const reqBytes = encodeLp(
      "swaralara/key-request/v1",
      uuidBytes(reqId),
      uuidBytes(recId),
      uuidBytes(holder.id),
      bytesHex(policyHash),
      bytesHex(reqHpkeSha),
      new Uint8Array(timeLong(now)),
      new Uint8Array(timeLong(now + 900000)),
      uuidBytes(crypto.randomUUID()),
    );
    const reqSig = holder.signature(reqBytes);

    const accessReqRes = await harness.request(
      holder.userId,
      "/access-requests",
      "POST",
      {
        id: reqId,
        recordingId: recId,
        requesterDeviceId: holder.id,
        requestHpkePublicKeysetBase64: b64(reqHpkePublic),
        requestBytesBase64: b64(reqBytes),
        requestSignatureBase64: reqSig,
        expiresAt: new Date(now + 900000).toISOString(),
      },
    );
    test.equal(accessReqRes.status, 200);
    test.equal(accessReqRes.data.state, "pending");

    // 5. GET /access-requests inbox
    const inbox = await harness.request(owner.userId, "/access-requests");
    test.equal(inbox.status, 200);
    test.equal(inbox.data.length >= 1, true);

    // 6. POST /access-requests/:id/decision by owner (approve)
    const relCipher1 = randomBytes(96);
    const relCipherSha1 = await sha(new Uint8Array(relCipher1));
    const relCtx1 = encodeLp(
      "swaralara/share-release/v1",
      uuidBytes(reqId),
      uuidBytes(recId),
      uuidBytes(holder.id),
      bytesHex(policyHash),
      bytesHex(await sha(reqBytes)),
      new Uint8Array(intBytes(1)), // shareIndex 1
      uuidBytes(owner.id),
      new Uint8Array(timeLong(now + 900000)),
      new Uint8Array(timeLong(now)),
      uuidBytes(crypto.randomUUID()),
    );
    const relSigPayload1 = encodeLp(
      "swaralara/share-release-signature/v1",
      relCtx1,
      bytesHex(relCipherSha1),
    );
    const decBytes1 = Buffer.from(`approve:${reqId}:1`, "ascii");

    const dec1 = await harness.request(
      owner.userId,
      `/access-requests/${reqId}/decision`,
      "POST",
      {
        decision: "approve",
        holderDeviceId: owner.id,
        shareIndex: 1,
        signedDecisionBase64: b64(decBytes1),
        decisionSignatureBase64: owner.signature(decBytes1),
        releaseCiphertextBase64: b64(relCipher1),
        contextBytesBase64: b64(relCtx1),
        holderSignatureBase64: owner.signature(relSigPayload1),
        ciphertextSha256: relCipherSha1,
      },
    );
    test.equal(dec1.status, 200);
    test.equal(dec1.data.decision, "approve");
    // With 1 approve, threshold (2) is not yet met
    test.equal(dec1.data.state, "pending");

    // 7. POST /access-requests/:id/decision by holder (approve own share)
    const relCipher2 = randomBytes(96);
    const relCipherSha2 = await sha(new Uint8Array(relCipher2));
    const relCtx2 = encodeLp(
      "swaralara/share-release/v1",
      uuidBytes(reqId),
      uuidBytes(recId),
      uuidBytes(holder.id),
      bytesHex(policyHash),
      bytesHex(await sha(reqBytes)),
      new Uint8Array(intBytes(2)), // shareIndex 2
      uuidBytes(holder.id),
      new Uint8Array(timeLong(now + 900000)),
      new Uint8Array(timeLong(now)),
      uuidBytes(crypto.randomUUID()),
    );
    const relSigPayload2 = encodeLp(
      "swaralara/share-release-signature/v1",
      relCtx2,
      bytesHex(relCipherSha2),
    );
    const decBytes2 = Buffer.from(`approve:${reqId}:2`, "ascii");

    const dec2 = await harness.request(
      holder.userId,
      `/access-requests/${reqId}/decision`,
      "POST",
      {
        decision: "approve",
        holderDeviceId: holder.id,
        shareIndex: 2,
        signedDecisionBase64: b64(decBytes2),
        decisionSignatureBase64: holder.signature(decBytes2),
        releaseCiphertextBase64: b64(relCipher2),
        contextBytesBase64: b64(relCtx2),
        holderSignatureBase64: holder.signature(relSigPayload2),
        ciphertextSha256: relCipherSha2,
      },
    );
    test.equal(dec2.status, 200);
    // With 2 approves, 2-of-3 threshold is MET -> state becomes 'ready'!
    test.equal(dec2.data.state, "ready");

    // 8. GET /access-requests/:id/releases
    const releasesRes = await harness.request(
      holder.userId,
      `/access-requests/${reqId}/releases?${await signedQuery(
        "release_list",
        reqId,
        await sha(reqBytes),
        now + 900000,
      )}`,
    );
    test.equal(releasesRes.status, 200);
    test.equal(releasesRes.data.length, 2);
    test.deepEqual(releasesRes.data.map((r: any) => r.shareIndex).sort(), [
      1,
      2,
    ]);
  });
});
