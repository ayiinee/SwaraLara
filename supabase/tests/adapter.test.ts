import { test } from "node:test";
import assert from "node:assert/strict";
import { startContractServer } from "./contract-server.ts";
import { supabasePorts } from "../functions/api/supabase-adapter.ts";
import { encryptedObjects, registration } from "./fixtures.ts";
import { trustProof } from "../functions/api/protocol.ts";

test("Supabase adapter verifies JWT through Auth and transports RPC over HTTP", async () => {
  const f = await startContractServer();
  try {
    const valid = f.issue(f.owner.userId).access_token;
    const ports = supabasePorts(f.origin, f.key, "not-a-service-secret");
    assert.equal((await ports.auth.getUser(valid))?.id, f.owner.userId);
    assert.equal(await ports.auth.getUser(valid.slice(0, -2) + "xx"), null);
    const expired = f.issue(f.owner.userId, -1).access_token;
    assert.equal(await ports.auth.getUser(expired), null);
    await assert.rejects(ports.db.call(f.owner.userId, "devices"));
    const publicResponse = await fetch(
      `${f.origin}/functions/v1/api/bootstrap`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${valid}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ displayName: "Network test" }),
      },
    );
    assert.equal(publicResponse.status, 200);
  } finally {
    await f.close();
  }
});

test("production API adapter uploads immutable ciphertext and verifies Storage bytes over HTTP", async () => {
  const f = await startContractServer();
  try {
    const jwt = f.issue(f.owner.userId).access_token;
    const call = async (path: string, body: any, method = "POST") => {
      const r = await fetch(`${f.origin}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${jwt}`,
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: r.status, ...await r.json() };
    };
    const api = (path: string, p?: any, method = "POST") =>
      call(`/functions/v1/api${path}`, p, method);
    assert.equal(
      (await api("/bootstrap", { displayName: "Storage test" })).status,
      200,
    );
    assert.equal((await api("/devices", f.owner.data)).status, 200);
    const paired = await call("/__test__/pair", { ownerDeviceId: f.owner.id });
    assert.equal(paired.status, 200);
    const link = paired.data.linkId;
    assert.equal(
      (await api(`/trust/${link}/confirm`, {
        deviceId: f.owner.id,
        signatureBase64: f.owner.signature(trustProof(link, f.owner.id)),
      })).data.state,
      "active",
    );
    const p = registration(f.owner, f.holder);
    assert.equal((await api("/recordings", p)).status, 200);
    for (const [index, o] of encryptedObjects(p.id).entries()) {
      const u = await api(`/recordings/${p.id}/segments/upload-url`, {
        index,
        objectHash: o.hash,
      });
      assert.equal(u.status, 200);
      const upload = () =>
        fetch(u.data.uploadUrl, {
          method: "PUT",
          headers: {
            "content-type": "application/octet-stream",
            "x-upsert": "false",
          },
          body: o.bytes,
        });
      assert.equal((await upload()).status, 200);
      assert.equal((await upload()).status, 409);
      const commit = await api(`/recordings/${p.id}/segments/commit`, {
        index,
        objectHash: o.hash,
      });
      assert.equal(commit.status, 200, JSON.stringify(commit));
      const retry = await api(`/recordings/${p.id}/segments/commit`, {
        index,
        objectHash: o.hash,
      });
      assert.deepEqual(retry.data, commit.data);
      const read = await api(
        `/recordings/${p.id}/segments/${index}/read-url`,
        {},
      );
      assert.equal(read.status, 200);
      const downloaded = await fetch(read.data.readUrl);
      assert.equal(downloaded.status, 200);
      assert.deepEqual(
        new Uint8Array(await downloaded.arrayBuffer()),
        new Uint8Array(o.bytes),
      );
      const denied = new URL(read.data.readUrl);
      denied.searchParams.set(
        "token",
        f.issue(f.owner.userId, -1).access_token,
      );
      assert.equal((await fetch(denied)).status, 403);
    }
    assert.equal(f.objects.size, 2);
    assert.equal(
      (await api(`/recordings/${p.id}`, undefined, "GET")).data.sync_state,
      "synced",
    );
  } finally {
    await f.close();
  }
});
