import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { database, ports } from "./harness.ts";
import {
  encryptedObjects,
  identity,
  registration,
  seedThroughApi,
} from "./fixtures.ts";
import {
  derToRaw,
  segment,
  strictJson,
  trustProof,
} from "../functions/api/protocol.ts";
let db: any, h: any, actors: any;
before(async () => {
  db = await database();
  h = ports(db);
  actors = await seedThroughApi(db, h);
});
after(async () => {
  await db?.close();
});

test("deny direct table/RPC/storage access even with unrelated permissive policy", async () => {
  const tables = (await db.query(
    "select tablename from pg_tables where schemaname='public'",
  )).rows;
  assert.equal(tables.length, 15);
  for (const role of ["anon", "authenticated"]) {
    await db.exec(`set role ${role}`);
    try {
      for (const { tablename } of tables) {
        await assert.rejects(
          db.query(`select * from public.${tablename}`),
          /permission denied/,
        );
      }
      await assert.rejects(
        db.query("select public.swl_m2($1,'devices','{}')", [
          actors.owner.userId,
        ]),
        /permission denied/,
      );
      assert.equal(
        (await db.query(
          "select count(*)::int as n from storage.objects where bucket_id='swl-recordings'",
        )).rows[0].n,
        0,
      );
      await assert.rejects(
        db.query(
          "insert into storage.objects(bucket_id,name) values('swl-recordings','x')",
        ),
        /row-level security/,
      );
    } finally {
      await db.exec("reset role");
    }
  }
});
test("unauthenticated/expired token and forged actor body fail closed", async () => {
  assert.equal((await h.request("expired", "/devices/me")).status, 401);
  assert.equal(
    (await h.request(actors.owner.userId, "/bootstrap", "POST", {
      displayName: "x",
      userId: actors.other.userId,
    })).status,
    422,
  );
  const health = await h.api(
    new Request("http://localhost/functions/v1/api/health"),
  );
  assert.equal(health.status, 200);
});
test("device proof rejects altered key, private keyset and device ownership takeover", async () => {
  const d = await identity();
  await db.query("insert into auth.users values($1)", [d.userId]);
  h.users.set(d.userId, d.userId);
  await h.request(d.userId, "/bootstrap", "POST", {
    displayName: "Device test",
  });
  assert.equal(
    (await h.request(d.userId, "/devices", "POST", {
      ...d.data,
      id: crypto.randomUUID(),
    })).status,
    403,
  );
  const keyset = JSON.parse(
    Buffer.from(d.data.hpkePublicKeysetBase64, "base64").toString(),
  );
  keyset.key[0].keyData.keyMaterialType = "ASYMMETRIC_PRIVATE";
  assert.equal(
    (await h.request(d.userId, "/devices", "POST", {
      ...d.data,
      hpkePublicKeysetBase64: Buffer.from(JSON.stringify(keyset)).toString(
        "base64",
      ),
    })).status,
    422,
  );
  assert.equal(
    (await h.request(
      actors.other.userId,
      "/devices",
      "POST",
      actors.owner.data,
    )).status,
    404,
  );
});
test("invitation expires/consumes once and link needs both device signatures", async () => {
  const invited = await h.request(
    actors.other.userId,
    "/trust/invitations",
    "POST",
    { deviceId: actors.other.id },
  );
  await db.query(
    "update trust_invitations set expires_at=now()-interval '1 second' where id=$1",
    [invited.data.id],
  );
  assert.equal(
    (await h.request(actors.holder.userId, "/trust/accept", "POST", {
      deviceId: actors.holder.id,
      token: invited.data.token,
    })).status,
    410,
  );
  const i = await h.request(actors.other.userId, "/trust/invitations", "POST", {
    deviceId: actors.other.id,
  });
  const a = await h.request(actors.holder.userId, "/trust/accept", "POST", {
    deviceId: actors.holder.id,
    token: i.data.token,
  });
  assert.equal(a.data.state, "pending");
  assert.equal(
    (await h.request(actors.holder.userId, "/trust/accept", "POST", {
      deviceId: actors.holder.id,
      token: i.data.token,
    })).status,
    409,
  );
  const link = a.data.id;
  const first = await h.request(
    actors.other.userId,
    `/trust/${link}/confirm`,
    "POST",
    {
      deviceId: actors.other.id,
      signatureBase64: actors.other.signature(
        trustProof(link, actors.other.id),
      ),
    },
  );
  assert.equal(first.data.state, "pending");
  assert.equal(
    (await h.request(actors.owner.userId, `/trust/${link}/confirm`, "POST", {
      deviceId: actors.owner.id,
      signatureBase64: actors.owner.signature(
        trustProof(link, actors.owner.id),
      ),
    })).status,
    404,
  );
});
test("immutable signed policy pins members, rejects demo and changed fingerprints", async () => {
  const p = registration(actors.owner, actors.holder);
  assert.equal(
    (await h.request(actors.owner.userId, "/recordings", "POST", {
      ...p,
      policyCode: "demo_2of3",
    })).status,
    422,
  );
  const bad = registration(actors.owner, {
    ...actors.holder,
    hpkeFingerprint: "0".repeat(64),
  });
  assert.equal(
    (await h.request(actors.owner.userId, "/recordings", "POST", bad)).status,
    409,
  );
  assert.equal(
    (await h.request(actors.owner.userId, "/recordings", "POST", p)).status,
    200,
  );
  assert.equal(
    (await h.request(actors.owner.userId, "/recordings", "POST", p)).status,
    200,
  );
  assert.equal(
    (await h.request(actors.owner.userId, "/recordings", "POST", {
      ...p,
      totalSamples: 12,
    })).status,
    409,
  );
  await assert.rejects(
    db.query("update recordings set sample_rate=48000 where id=$1", [p.id]),
    /IMMUTABLE/,
  );
});
test("A/B isolation and member permissions cover reads/uploads/commit/audit/path injection", async () => {
  const p = registration(actors.owner, actors.holder);
  await h.request(actors.owner.userId, "/recordings", "POST", p);
  for (
    const [method, suffix, body] of [
      ["GET", "", undefined],
      ["GET", "/segments", undefined],
      ["GET", "/audit", undefined],
      ["POST", "/segments/upload-url", {
        index: 0,
        objectHash: "0".repeat(64),
      }],
      ["POST", "/segments/commit", { index: 0, objectHash: "0".repeat(64) }],
      ["POST", "/segments/0/read-url", {}],
    ] as any[]
  ) {
    assert.equal(
      (await h.request(
        actors.other.userId,
        `/recordings/${p.id}${suffix}`,
        method,
        body,
      )).status,
      404,
    );
  }
  assert.equal(
    (await h.request(actors.holder.userId, `/recordings/${p.id}`)).status,
    200,
  );
  assert.equal(
    (await h.request(actors.holder.userId, `/recordings/${p.id}/segments`))
      .status,
    404,
  );
  assert.equal(
    (await h.request(actors.other.userId, "/recordings")).data.items.length,
    0,
  );
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/upload-url`,
      "POST",
      {
        index: 0,
        objectHash: "0".repeat(64),
        path: `${actors.other.userId}/x`,
      },
    )).status,
    422,
  );
});
test("verified commit handles loss before/after upload and lost receipt idempotently", async () => {
  const p = registration(actors.owner, actors.holder);
  await h.request(actors.owner.userId, "/recordings", "POST", p);
  const objects = encryptedObjects(p.id);
  const url = await h.request(
    actors.owner.userId,
    `/recordings/${p.id}/segments/upload-url`,
    "POST",
    { index: 0, objectHash: objects[0].hash },
  );
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/commit`,
      "POST",
      { index: 0, objectHash: objects[0].hash },
    )).status,
    409,
  );
  h.objects.set(url.data.storagePath, objects[0].bytes);
  h.interruptStorage();
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/commit`,
      "POST",
      { index: 0, objectHash: objects[0].hash },
    )).status,
    503,
  );
  const receipt = await h.request(
    actors.owner.userId,
    `/recordings/${p.id}/segments/commit`,
    "POST",
    { index: 0, objectHash: objects[0].hash },
  );
  assert.equal(receipt.status, 200, JSON.stringify(receipt));
  const retry = await h.request(
    actors.owner.userId,
    `/recordings/${p.id}/segments/commit`,
    "POST",
    { index: 0, objectHash: objects[0].hash },
  );
  assert.deepEqual(retry.data, receipt.data);
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/commit`,
      "POST",
      { index: 0, objectHash: "0".repeat(64) },
    )).status,
    409,
  );
  const next = await h.request(
    actors.owner.userId,
    `/recordings/${p.id}/segments/upload-url`,
    "POST",
    { index: 1, objectHash: objects[1].hash },
  );
  h.objects.set(next.data.storagePath, objects[1].bytes);
  const concurrent = await Promise.all(
    [0, 1].map(() =>
      h.request(
        actors.owner.userId,
        `/recordings/${p.id}/segments/commit`,
        "POST",
        { index: 1, objectHash: objects[1].hash },
      )
    ),
  );
  assert(concurrent.every((x) => x.status === 200));
  assert.equal(
    (await db.query(
      "select count(*)::int as n from recording_segments where recording_id=$1",
      [p.id],
    )).rows[0].n,
    2,
  );
  const detail = await h.request(actors.owner.userId, `/recordings/${p.id}`);
  assert.equal(detail.data.sync_state, "synced");
  assert.equal(detail.data.recovery_state, "degraded");
  await assert.rejects(
    db.query("delete from recording_segments where recording_id=$1", [p.id]),
    /IMMUTABLE/,
  );
});
test("header corruption and declaration/hash mismatch never create committed metadata", async () => {
  const p = registration(actors.owner, actors.holder);
  await h.request(actors.owner.userId, "/recordings", "POST", p);
  const o = encryptedObjects(p.id)[0];
  const path = `${actors.owner.userId}/${p.id}/segments/0000000000.swseg`;
  const bad = Buffer.from(o.bytes);
  bad[0] ^= 1;
  h.objects.set(path, bad);
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/commit`,
      "POST",
      { index: 0, objectHash: o.hash },
    )).status,
    422,
  );
  h.objects.set(path, o.bytes);
  assert.equal(
    (await h.request(
      actors.owner.userId,
      `/recordings/${p.id}/segments/commit`,
      "POST",
      { index: 0, objectHash: "0".repeat(64) },
    )).status,
    409,
  );
  assert.equal(
    (await db.query(
      "select count(*)::int as n from recording_segments where recording_id=$1",
      [p.id],
    )).rows[0].n,
    0,
  );
});
test("request bounds reject malformed UTF-8, oversized bodies and excess attempts", async () => {
  const headers = {
    authorization: `Bearer ${actors.owner.userId}`,
    "content-type": "application/json",
  };
  const bad = await h.api(
    new Request("http://localhost/functions/v1/api/bootstrap", {
      method: "POST",
      headers,
      body: new Uint8Array([0xc0, 0xaf]),
    }),
  );
  assert.equal(bad.status, 400);
  assert.equal(
    (await h.request(actors.owner.userId, "/bootstrap", "POST", {
      displayName: "a".repeat(17000),
    })).status,
    413,
  );
  const actor = crypto.randomUUID();
  h.users.set(actor, actor);
  await db.query("insert into auth.users values($1)", [actor]);
  for (let i = 0; i < 10; i++) {
    assert.equal(
      (await h.request(actor, "/devices", "POST", { id: "invalid" })).status,
      422,
    );
  }
  assert.equal(
    (await h.request(actor, "/devices", "POST", { id: "invalid" })).status,
    429,
  );
});

test("strict parsing rejects duplicate/escaped keys, trailing bytes and invalid ASN.1", () => {
  for (
    const text of [
      '{"id":1,"id":2}',
      '{"id":1,"\\u0069d":2}',
      '{"__proto__":1,"__proto__":2}',
      "{}{}",
      '{"x":NaN}',
    ]
  ) assert.throws(() => strictJson(text));
  assert.throws(() => derToRaw(new Uint8Array([0x30, 6, 2, 1, 0x80, 2, 1, 1])));
  const o = encryptedObjects(crypto.randomUUID())[0];
  assert.throws(() =>
    segment(o.bytes.slice(0, -1), crypto.randomUUID(), 0, 16000)
  );
});
