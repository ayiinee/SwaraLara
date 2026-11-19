import assert from "node:assert/strict";
import { test } from "node:test";
import { randomBytes } from "node:crypto";
import {
  b64,
  bytesHex,
  encodeLp,
  sha,
  uuidBytes,
} from "../functions/api/protocol.ts";
import { encryptedObjects } from "./fixtures.ts";
import { setup } from "./m3-test-support.ts";

test("M3 denial is explicit, idempotent and prevents a later approval or download", async (t) => {
  const f = await setup(t), r = await f.request();
  await r.send();
  const signed = Buffer.from(`deny:${r.id}:1`);
  const body = {
    decision: "deny",
    holderDeviceId: f.owner.id,
    shareIndex: 1,
    signedDecisionBase64: b64(signed),
    decisionSignatureBase64: f.owner.signature(signed),
  };
  const root = `/access-requests/${r.id}`;
  const denied = await f.h.request(
    f.owner.userId,
    `${root}/decision`,
    "POST",
    body,
  );
  assert.equal(denied.status, 200);
  assert.equal(denied.data.state, "denied");
  assert.equal(
    (await f.h.request(f.owner.userId, `${root}/decision`, "POST", body))
      .status,
    200,
  );
  assert.equal((await (await f.decision(r)).send()).status, 409);
  const auth = actionQuery(await f.action("release_list", r));
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/recording?${auth}`)).status,
    409,
  );
});

function actionQuery(a: any) {
  return new URLSearchParams({
    deviceId: a.deviceId,
    actionBase64: a.actionBytesBase64,
    signatureBase64: a.signatureBase64,
  });
}

test("M3 roster carries proof bytes only to paired users and recording members", async (t) => {
  const f = await setup(t);
  const trust = await f.h.request(f.owner.userId, "/trust");
  assert.equal(trust.status, 200);
  assert.equal(
    trust.data[0].holderDevice.proofSignatureBase64,
    f.holder.data.proofSignatureBase64,
  );
  const members = await f.h.request(
    f.holder.userId,
    `/recordings/${f.reg.id}/members`,
  );
  assert.equal(members.status, 200);
  assert.equal(members.data.length, 2);
  assert.equal(
    members.data[0].hpkePublicKeysetBase64,
    f.owner.data.hpkePublicKeysetBase64,
  );
  assert.equal(
    (await f.h.request(f.other.userId, `/recordings/${f.reg.id}/members`))
      .status,
    404,
  );
  const inbox = await f.h.request(
    f.holder.userId,
    `/m3/recordings?deviceId=${f.holder.id}`,
  );
  assert.equal(inbox.status, 200);
  assert.equal(inbox.data[0].id, f.reg.id);
  assert.equal(
    (await f.h.request(
      f.other.userId,
      `/m3/recordings?deviceId=${f.holder.id}`,
    )).status,
    404,
  );
});

test("M3 upload retry returns bound receipts and owner receives original signed acknowledgment", async (t) => {
  const f = await setup(t),
    cipher = randomBytes(80),
    digest = await sha(cipher);
  const index = Buffer.alloc(4);
  index.writeUInt32BE(2);
  const context = encodeLp(
    "swaralara/share-envelope/v1",
    uuidBytes(f.reg.id),
    bytesHex(f.policyHash),
    index,
    uuidBytes(f.holder.id),
  );
  const envelope = {
    shareIndex: 2,
    holderDeviceId: f.holder.id,
    schemeVersion: "shamir-bc-gf256-v1",
    envelopeCiphertextBase64: b64(cipher),
    contextBytesBase64: b64(context),
    ciphertextSha256: digest,
    ownerSignatureBase64: f.owner.signature(
      encodeLp(
        "swaralara/share-envelope-signature/v1",
        context,
        bytesHex(digest),
      ),
    ),
  };
  const url = `/recordings/${f.reg.id}/share-envelopes`;
  const upload = await f.h.request(f.owner.userId, url, "POST", {
    envelopes: [envelope],
  });
  assert.equal(upload.status, 200);
  assert.equal(upload.data.receipts[0].ciphertextHash, digest);
  assert.deepEqual(
    (await f.h.request(f.owner.userId, url, "POST", { envelopes: [envelope] }))
      .data,
    upload.data,
  );
  const r = await f.request(),
    ack = await f.action("share_ack", r, f.holder, digest);
  assert.equal(
    (await f.h.request(
      f.holder.userId,
      `/recordings/${f.reg.id}/my-share/ack`,
      "POST",
      ack,
    )).status,
    200,
  );
  const acks = await f.h.request(
    f.owner.userId,
    `/recordings/${f.reg.id}/acknowledgments`,
  );
  assert.equal(acks.status, 200);
  assert.equal(acks.data[0].payloadBase64, ack.actionBytesBase64);
  assert.equal(acks.data[0].signatureBase64, ack.signatureBase64);
  assert.equal(
    (await f.h.request(
      f.holder.userId,
      `/recordings/${f.reg.id}/acknowledgments`,
    )).status,
    404,
  );
});

test("M3 decision retry is idempotent; encrypted download requires ready state and requester proof", async (t) => {
  const f = await setup(t), r = await f.request();
  assert.equal((await r.send()).status, 200);
  const a = await f.decision(r), b = await f.decision(r, f.holder, 2);
  const auth = await f.action("release_list", r), query = actionQuery(auth);
  const root = `/access-requests/${r.id}`;
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/recording?${query}`)).status,
    409,
  );
  assert.equal((await a.send()).status, 200);
  assert.equal((await a.send()).status, 200);
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/recording?${query}`)).status,
    409,
  );
  assert.equal((await b.send()).status, 200);
  assert.equal((await b.send()).status, 200);
  for (const object of encryptedObjects(f.reg.id)) {
    const path = `${f.owner.userId}/${f.reg.id}/segments/${
      String(object.index).padStart(10, "0")
    }.swseg`;
    f.h.objects.set(path, object.bytes);
    assert.equal(
      (await f.h.request(
        f.owner.userId,
        `/recordings/${f.reg.id}/segments/commit`,
        "POST",
        { index: object.index, objectHash: object.hash },
      )).status,
      200,
    );
  }
  const metadata = await f.h.request(
    f.holder.userId,
    `${root}/recording?${query}`,
  );
  assert.equal(metadata.status, 200);
  assert.equal(metadata.data.totalSamples, 11);
  const page = await f.h.request(
    f.holder.userId,
    `${root}/segments?offset=0&${query}`,
  );
  assert.equal(page.status, 200);
  assert.equal(page.data.length, 2);
  assert.match(page.data[0].readUrl, /^https:\/\/storage\.test\/read\//);
  assert.equal(
    (await f.h.request(f.other.userId, `${root}/segments?${query}`)).status,
    404,
  );
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/segments`)).status,
    422,
  );
});

test("M3 cancellation retains signed bytes, retries safely and revokes recovery download", async (t) => {
  const f = await setup(t), r = await f.request();
  await r.send();
  await (await f.decision(r)).send();
  await (await f.decision(r, f.holder, 2)).send();
  const cancel = await f.action("request_cancel", r),
    root = `/access-requests/${r.id}`;
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/cancel`, "POST", cancel))
      .status,
    200,
  );
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/cancel`, "POST", cancel))
      .status,
    200,
  );
  const detail = await f.h.request(f.owner.userId, root);
  assert.equal(
    detail.data.cancellation.payloadBase64,
    cancel.actionBytesBase64,
  );
  const auth = actionQuery(await f.action("release_list", r));
  assert.equal(
    (await f.h.request(f.holder.userId, `${root}/recording?${auth}`)).status,
    409,
  );
});
