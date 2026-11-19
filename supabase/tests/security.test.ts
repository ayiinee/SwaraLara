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

import { int, setup } from "./m3-test-support.ts";

test("request expiry must equal signed expiry", async (t) => {
  const f = await setup(t),
    r = await f.request({
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
    });
  assert.equal((await r.send()).status, 422);
});
test("request public HPKE key must equal signed key hash", async (t) => {
  const f = await setup(t),
    r = await f.request({
      requestHpkePublicKeysetBase64: f.owner.data.hpkePublicKeysetBase64,
    });
  assert.equal((await r.send()).status, 422);
});
test("signed request nonce cannot be reused under another request id", async (t) => {
  const f = await setup(t), first = await f.request();
  assert.equal((await first.send()).status, 200);
  const second = await f.request();
  const fields = (await import("../functions/api/protocol.ts")).decodeLp(
    Buffer.from(second.body.requestBytesBase64, "base64"),
  );
  fields[8] = uuidBytes(first.nonce);
  const raw = encodeLp("swaralara/key-request/v1", ...fields.slice(1));
  second.body.requestBytesBase64 = b64(raw);
  second.body.requestSignatureBase64 = f.holder.signature(raw);
  assert.equal((await second.send()).status, 409);
});
test("request id retry cannot replace bound request bytes", async (t) => {
  const f = await setup(t), r = await f.request();
  assert.equal((await r.send()).status, 200);
  const second = await f.request({ id: r.id });
  const fields = (await import("../functions/api/protocol.ts")).decodeLp(
    Buffer.from(second.body.requestBytesBase64, "base64"),
  );
  fields[1] = uuidBytes(r.id);
  const raw = encodeLp("swaralara/key-request/v1", ...fields.slice(1));
  second.body.requestBytesBase64 = b64(raw);
  second.body.requestSignatureBase64 = f.holder.signature(raw);
  assert.equal((await second.send()).status, 409);
});
test("release signed for another request cannot approve this request", async (t) => {
  const f = await setup(t), a = await f.request(), b = await f.request();
  assert.equal((await a.send()).status, 200);
  assert.equal((await b.send()).status, 200);
  const d = await f.decision(a);
  assert.equal(
    (await f.h.request(
      f.owner.userId,
      `/access-requests/${b.id}/decision`,
      "POST",
      d.body,
    )).status,
    422,
  );
});
test("repeated concurrent approval from same holder never meets threshold", async (t) => {
  const f = await setup(t), r = await f.request();
  assert.equal((await r.send()).status, 200);
  const d = await f.decision(r);
  const responses = await Promise.all([d.send(), d.send(), d.send()]);
  assert(responses.every((x) => x.status === 200 || x.status === 409));
  const detail = await f.h.request(f.holder.userId, `/access-requests/${r.id}`);
  assert.equal(detail.data.state, "pending");
  assert.equal(detail.data.decisions.length, 1);
});
test("distinct concurrent approvals meet owner-required threshold atomically", async (t) => {
  const f = await setup(t), r = await f.request();
  assert.equal((await r.send()).status, 200);
  const a = await f.decision(r), b = await f.decision(r, f.holder, 2);
  assert(
    (await Promise.all([a.send(), b.send()])).every((x) => x.status === 200),
  );
  assert.equal(
    (await f.h.request(f.holder.userId, `/access-requests/${r.id}`)).data.state,
    "ready",
  );
  assert.equal(
    (await f.db.query(
      "select count(*)::int n from share_releases where request_id=$1",
      [r.id],
    )).rows[0].n,
    2,
  );
});
test("expired ready request cannot return releases", async (t) => {
  const f = await setup(t), r = await f.request();
  await r.send();
  await (await f.decision(r)).send();
  await (await f.decision(r, f.holder, 2)).send();
  // Clock fault injection at DB boundary, without a wall-clock sleep.
  await f.db.query(
    "update access_requests set created_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' where id=$1",
    [r.id],
  );
  assert.equal(
    (await f.h.request(f.holder.userId, `/access-requests/${r.id}/releases`))
      .status,
    410,
  );
});
test("cancel ready request closes it and blocks subsequent release reads", async (t) => {
  const f = await setup(t), r = await f.request();
  await r.send();
  await (await f.decision(r)).send();
  await (await f.decision(r, f.holder, 2)).send();
  const cancel = await f.action("request_cancel", r);
  const result = await f.h.request(
    f.holder.userId,
    `/access-requests/${r.id}/cancel`,
    "POST",
    cancel,
  );
  assert.equal(result.status, 200);
  assert.equal(result.data.state, "cancelled");
  assert.equal(
    (await f.h.request(f.holder.userId, `/access-requests/${r.id}/releases`))
      .status,
    409,
  );
});
test("release read requires requester device signature", async (t) => {
  const f = await setup(t), r = await f.request();
  await r.send();
  await (await f.decision(r)).send();
  await (await f.decision(r, f.holder, 2)).send();
  assert.equal(
    (await f.h.request(f.holder.userId, `/access-requests/${r.id}/releases`))
      .status,
    422,
  );
});
test("acknowledgment binds envelope hash and policy", async (t) => {
  const f = await setup(t), r = await f.request();
  const cipher = randomBytes(128), digest = await sha(cipher);
  const ctx = encodeLp(
    "swaralara/share-envelope/v1",
    uuidBytes(f.reg.id),
    bytesHex(f.policyHash),
    int(2),
    uuidBytes(f.holder.id),
  );
  const env = {
    shareIndex: 2,
    holderDeviceId: f.holder.id,
    schemeVersion: "shamir-bc-gf256-v1",
    envelopeCiphertextBase64: b64(cipher),
    contextBytesBase64: b64(ctx),
    ownerSignatureBase64: f.owner.signature(
      encodeLp("swaralara/share-envelope-signature/v1", ctx, bytesHex(digest)),
    ),
    ciphertextSha256: digest,
  };
  assert.equal(
    (await f.h.request(
      f.owner.userId,
      `/recordings/${f.reg.id}/share-envelopes`,
      "POST",
      { envelopes: [env] },
    )).status,
    200,
  );
  const wrong = await f.action("share_ack", r, f.holder, "f".repeat(64));
  assert.equal(
    (await f.h.request(
      f.holder.userId,
      `/recordings/${f.reg.id}/my-share/ack`,
      "POST",
      wrong,
    )).status,
    422,
  );
});
