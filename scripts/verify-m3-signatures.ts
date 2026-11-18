// Public synthetic JVM/Android vectors. Uses the existing production DER -> WebCrypto verifier.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { decodePolicy, verify } from "../supabase/functions/api/protocol.ts";

function lp(bytes: Uint8Array): Buffer[] {
  const data = Buffer.from(bytes);
  const result: Buffer[] = [];
  let offset = 0;
  while (offset < data.length) {
    assert(offset + 4 <= data.length);
    const n = data.readUInt32BE(offset);
    offset += 4;
    assert(n <= 8192 && offset + n <= data.length);
    result.push(data.subarray(offset, offset + n));
    offset += n;
  }
  return result;
}
function shape(bytes: Uint8Array, domain: string, sizes: number[]): Buffer[] {
  const fields = lp(bytes);
  assert.equal(fields[0].toString("ascii"), domain);
  assert.deepEqual(fields.slice(1).map((f) => f.length), sizes);
  return fields;
}

const path = process.argv[2] ??
  new URL("../docs/fixtures/m3-public-signatures-v1.json", import.meta.url);
const fixture = JSON.parse(await readFile(path, "utf8"));
assert.equal(fixture.schema, "swl-m3-public-signatures-v1");
assert.equal(fixture.synthetic, true);
assert(["android", "jvm"].includes(fixture.origin));
assert.equal(fixture.vectors.length, 6);
const names = new Set<string>();
for (const v of fixture.vectors) {
  assert(!names.has(v.name));
  names.add(v.name);
  const spki = new Uint8Array(Buffer.from(v.spkiBase64, "base64"));
  const payload = new Uint8Array(Buffer.from(v.payloadBase64, "base64"));
  const signature = new Uint8Array(Buffer.from(v.signatureBase64, "base64"));
  if (v.name === "policy") {
    assert.equal(decodePolicy(payload).members.length, 2);
  }
  if (v.name === "envelope" || v.name === "release") {
    const domain = v.name === "envelope" ? "share-envelope" : "share-release";
    const outer = lp(payload);
    assert.equal(
      outer[0].toString("ascii"),
      `swaralara/${domain}-signature/v1`,
    );
    assert.equal(outer.length, 3);
    assert.equal(outer[2].length, 32);
    shape(
      outer[1],
      `swaralara/${domain}/v1`,
      v.name === "envelope"
        ? [16, 32, 4, 16]
        : [16, 16, 16, 32, 32, 4, 16, 8, 8, 16],
    );
  }
  if (v.name === "request") {
    const fields = shape(payload, "swaralara/key-request/v1", [
      16,
      16,
      16,
      32,
      32,
      8,
      8,
      16,
    ]);
    const duration = fields[7].readBigInt64BE() - fields[6].readBigInt64BE();
    assert(duration > 0n && duration <= 900000n);
  }
  if (v.name === "ack" || v.name === "cancel") {
    const fields = lp(payload);
    assert.equal(
      fields[1].toString("ascii"),
      v.name === "ack" ? "share_ack" : "request_cancel",
    );
    shape(payload, "swaralara/device-action/v1", [
      fields[1].length,
      16,
      16,
      16,
      32,
      32,
      8,
      8,
      16,
    ]);
  }
  await verify(spki, payload, signature);
  const altered = payload.slice();
  altered[altered.length - 1] ^= 1;
  await assert.rejects(() => verify(spki, altered, signature));
  await assert.rejects(() =>
    verify(spki, payload, new Uint8Array([...signature, 0]))
  );
  process.stdout.write(
    `PASS ${v.name}: ${fixture.origin} JCA DER verified; altered payload and trailing signature rejected\n`,
  );
}
assert.deepEqual([...names].sort(), [
  "ack",
  "cancel",
  "envelope",
  "policy",
  "release",
  "request",
]);
process.stdout.write(
  `6 public ${fixture.origin}/WebCrypto signature vectors passed. No private keys or plaintext shares in fixture.\n`,
);
