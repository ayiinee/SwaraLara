import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  b64,
  bytesHex,
  encodeLp,
  sha,
  uuidBytes,
} from "../functions/api/protocol.ts";
import { registration, seedThroughApi } from "./fixtures.ts";
import { database, ports } from "./harness.ts";

export const int = (n: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const time = (n: number) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64BE(BigInt(n));
  return b;
};
export async function setup(t: any) {
  const db = await database();
  t.after(() => db.close());
  const h = ports(db), peers = await seedThroughApi(db, h);
  const reg = registration(peers.owner, peers.holder);
  assert.equal(
    (await h.request(peers.owner.userId, "/recordings", "POST", reg)).status,
    200,
  );
  const policyHash = await sha(Buffer.from(reg.policySnapshotBase64, "base64"));
  async function request(overrides: any = {}) {
    const id = crypto.randomUUID(), now = Date.now(), expires = now + 60000;
    const publicBytes = Buffer.from(
      peers.holder.data.hpkePublicKeysetBase64,
      "base64",
    );
    const nonce = crypto.randomUUID();
    const raw = encodeLp(
      "swaralara/key-request/v1",
      uuidBytes(id),
      uuidBytes(reg.id),
      uuidBytes(peers.holder.id),
      bytesHex(policyHash),
      bytesHex(await sha(publicBytes)),
      time(now),
      time(expires),
      uuidBytes(nonce),
    );
    const body = {
      id,
      recordingId: reg.id,
      requesterDeviceId: peers.holder.id,
      requestHpkePublicKeysetBase64: b64(publicBytes),
      requestBytesBase64: b64(raw),
      requestSignatureBase64: peers.holder.signature(raw),
      expiresAt: new Date(expires).toISOString(),
      ...overrides,
    };
    return {
      id,
      now,
      expires,
      nonce,
      raw,
      body,
      send: () =>
        h.request(peers.holder.userId, "/access-requests", "POST", body),
    };
  }
  async function decision(
    r: any,
    peer = peers.owner,
    index = 1,
    overrides: any = {},
  ) {
    const cipher = randomBytes(96), digest = await sha(cipher);
    const ctx = encodeLp(
      "swaralara/share-release/v1",
      uuidBytes(r.id),
      uuidBytes(reg.id),
      uuidBytes(peers.holder.id),
      bytesHex(policyHash),
      bytesHex(await sha(r.raw)),
      int(index),
      uuidBytes(peer.id),
      time(r.expires),
      time(r.now),
      uuidBytes(crypto.randomUUID()),
    );
    const signed = Buffer.from(`approve:${r.id}:${index}`);
    const body = {
      decision: "approve",
      holderDeviceId: peer.id,
      shareIndex: index,
      signedDecisionBase64: b64(signed),
      decisionSignatureBase64: peer.signature(signed),
      releaseCiphertextBase64: b64(cipher),
      contextBytesBase64: b64(ctx),
      holderSignatureBase64: peer.signature(
        encodeLp("swaralara/share-release-signature/v1", ctx, bytesHex(digest)),
      ),
      ciphertextSha256: digest,
      ...overrides,
    };
    return {
      body,
      send: () =>
        h.request(
          peer.userId,
          `/access-requests/${r.id}/decision`,
          "POST",
          body,
        ),
    };
  }
  function action(name: string, r: any, peer = peers.holder, object = "") {
    return (async () => {
      const raw = encodeLp(
        "swaralara/device-action/v1",
        Buffer.from(name),
        uuidBytes(reg.id),
        uuidBytes(name === "my_share" || name === "share_ack" ? reg.id : r.id),
        uuidBytes(peer.id),
        bytesHex(policyHash),
        bytesHex(object || await sha(r.raw)),
        time(r.now),
        time(r.expires),
        uuidBytes(crypto.randomUUID()),
      );
      return {
        deviceId: peer.id,
        actionBytesBase64: b64(raw),
        signatureBase64: peer.signature(raw),
      };
    })();
  }
  return { db, h, ...peers, reg, policyHash, request, decision, action };
}
