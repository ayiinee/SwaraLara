export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}
export function demand(
  ok: unknown,
  code = "INVALID",
  status = 422,
): asserts ok {
  if (!ok) throw new ApiError(status, code);
}
export const hex = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export const sha = async (b: Uint8Array) =>
  hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new Uint8Array(b).buffer),
    ),
  );
export const b64 = (b: Uint8Array) =>
  btoa(Array.from(b, (x) => String.fromCharCode(x)).join(""));
export function unbase64(s: unknown, max = 8192): Uint8Array {
  demand(
    typeof s === "string" && s.length <= Math.ceil(max / 3) * 4 &&
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        s,
      ),
  );
  const b = Uint8Array.from(atob(s), (x) => x.charCodeAt(0));
  demand(b.length <= max && b64(b) === s, "BASE64_CANONICAL");
  return b;
}
export function uuid(s: unknown): string {
  demand(
    typeof s === "string" &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(s),
  );
  return s;
}
export function hash(s: unknown): string {
  demand(typeof s === "string" && /^[0-9a-f]{64}$/.test(s));
  return s;
}
export function integer(n: unknown, min: number, max: number): number {
  demand(
    typeof n === "number" && Number.isSafeInteger(n) && n >= min && n <= max,
  );
  return n;
}
export function fields(p: unknown, names: string[]): any {
  demand(p !== null && typeof p === "object" && !Array.isArray(p));
  demand(Object.keys(p).every((k) => names.includes(k)));
  return p;
}
export function label(v: unknown, max = 80): string {
  demand(
    typeof v === "string" && v.length > 0 && v.length <= max &&
      // deno-lint-ignore no-control-regex -- Display labels must reject ASCII control characters.
      !/[\x00-\x1f]/.test(v),
  );
  return v;
}
export function concat(...parts: Uint8Array[]): Uint8Array {
  const o = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    o.set(p, i);
    i += p.length;
  }
  return o;
}
export function bytesHex(h: string): Uint8Array {
  demand(h.length % 2 === 0 && /^[a-f0-9]+$/.test(h));
  return Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
}
export const uuidBytes = (id: string) => bytesHex(uuid(id).replaceAll("-", ""));
export function uuidAt(b: Uint8Array, offset: number): string {
  const h = hex(b.slice(offset, offset + 16));
  demand(h.length === 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${
    h.slice(16, 20)
  }-${h.slice(20)}`;
}
export type Member = {
  shareIndex: number;
  userId: string;
  deviceId: string;
  hpkeFingerprint: string;
  signingFingerprint: string;
};
export type Policy = {
  id: string;
  ownerUserId: string;
  sourceDeviceId: string;
  policyCode: string;
  members: Member[];
};
export function policyBytes(p: Policy): Uint8Array {
  demand(
    p.members.length ===
      (p.policyCode === "owner_required_2of2"
        ? 2
        : p.policyCode === "recovery_2of3"
        ? 3
        : 0),
  );
  demand(
    new Set(p.members.map((m) => uuid(m.userId))).size === p.members.length,
  );
  demand(
    p.members[0].userId === p.ownerUserId &&
      p.members[0].deviceId === p.sourceDeviceId,
  );
  return concat(
    new TextEncoder().encode("SWP1"),
    uuidBytes(p.id),
    uuidBytes(p.ownerUserId),
    uuidBytes(p.sourceDeviceId),
    new Uint8Array([
      p.policyCode === "owner_required_2of2" ? 1 : 2,
      p.members.length,
    ]),
    ...p.members.map((m, i) => {
      demand(m.shareIndex === i + 1);
      return concat(
        new Uint8Array([m.shareIndex]),
        uuidBytes(m.userId),
        uuidBytes(m.deviceId),
        bytesHex(hash(m.hpkeFingerprint)),
        bytesHex(hash(m.signingFingerprint)),
      );
    }),
  );
}
export function decodePolicy(b: Uint8Array): Policy {
  demand(b.length >= 54 && new TextDecoder().decode(b.slice(0, 4)) === "SWP1");
  const count = b[53];
  demand(b.length === 54 + 97 * count);
  const p: Policy = {
    id: uuidAt(b, 4),
    ownerUserId: uuidAt(b, 20),
    sourceDeviceId: uuidAt(b, 36),
    policyCode: b[52] === 1
      ? "owner_required_2of2"
      : b[52] === 2
      ? "recovery_2of3"
      : "invalid",
    members: [],
  };
  for (let i = 0; i < count; i++) {
    const at = 54 + 97 * i;
    p.members.push({
      shareIndex: b[at],
      userId: uuidAt(b, at + 1),
      deviceId: uuidAt(b, at + 17),
      hpkeFingerprint: hex(b.slice(at + 33, at + 65)),
      signingFingerprint: hex(b.slice(at + 65, at + 97)),
    });
  }
  demand(hex(policyBytes(p)) === hex(b));
  return p;
}
export function derToRaw(der: Uint8Array): Uint8Array {
  demand(
    der.length >= 8 && der.length <= 72 && der[0] === 0x30 &&
      der[1] === der.length - 2,
    "BAD_SIGNATURE",
  );
  let pos = 2;
  const out = new Uint8Array(64);
  for (let i = 0; i < 2; i++) {
    demand(der[pos++] === 2, "BAD_SIGNATURE");
    const len = der[pos++];
    demand(len >= 1 && len <= 33 && pos + len <= der.length, "BAD_SIGNATURE");
    let n = der.slice(pos, pos + len);
    pos += len;
    demand(
      (n[0] & 0x80) === 0 &&
        !(n.length > 1 && n[0] === 0 && (n[1] & 0x80) === 0),
      "BAD_SIGNATURE",
    );
    if (n.length === 33) {
      demand(n[0] === 0, "BAD_SIGNATURE");
      n = n.slice(1);
    }
    out.set(n, 32 * (i + 1) - n.length);
  }
  demand(pos === der.length, "BAD_SIGNATURE");
  return out;
}
export async function verify(
  spki: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
) {
  try {
    const k = await crypto.subtle.importKey(
      "spki",
      new Uint8Array(spki).buffer,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    demand(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        k,
        new Uint8Array(derToRaw(signature)).buffer,
        new Uint8Array(payload).buffer,
      ),
      "BAD_SIGNATURE",
      403,
    );
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(422, "INVALID_SIGNING_KEY");
  }
}
export const deviceProof = async (
  id: string,
  hpke: Uint8Array,
  spki: Uint8Array,
) =>
  concat(
    new TextEncoder().encode("SWD2"),
    uuidBytes(id),
    bytesHex(await sha(hpke)),
    bytesHex(await sha(spki)),
  );
export const trustProof = (id: string, deviceId: string) =>
  concat(new TextEncoder().encode("SWT1"), uuidBytes(id), uuidBytes(deviceId));
export function validateHpkePublic(bytes: Uint8Array) {
  const protobuf = (b: Uint8Array): Map<number, number | Uint8Array> => {
    const out = new Map<number, number | Uint8Array>();
    let at = 0;
    const varint = () => {
      let n = 0, shift = 0;
      while (at < b.length && shift < 35) {
        const v = b[at++];
        n += (v & 127) * 2 ** shift;
        if (!(v & 128)) return n;
        shift += 7;
      }
      throw new ApiError(422, "HPKE_PUBLIC_KEY_REQUIRED");
    };
    while (at < b.length) {
      const tag = varint(), field = tag >> 3;
      demand(field > 0 && !out.has(field), "HPKE_PUBLIC_KEY_REQUIRED");
      if ((tag & 7) === 0) out.set(field, varint());
      else {
        demand((tag & 7) === 2, "HPKE_PUBLIC_KEY_REQUIRED");
        const len = varint();
        demand(at + len <= b.length, "HPKE_PUBLIC_KEY_REQUIRED");
        out.set(field, b.slice(at, at + len));
        at += len;
      }
    }
    return out;
  };
  const p = protobuf(bytes);
  demand(
    [...p.keys()].every((k) => [1, 2, 3].includes(k)) && (p.get(1) ?? 0) === 0,
    "HPKE_PUBLIC_KEY_REQUIRED",
  );
  const params = p.get(2), key = p.get(3);
  demand(
    params instanceof Uint8Array && key instanceof Uint8Array &&
      key.length === 32 && key.some((x) => x !== 0),
    "HPKE_PUBLIC_KEY_REQUIRED",
  );
  const q = protobuf(params);
  demand(
    q.size === 3 && q.get(1) === 1 && q.get(2) === 1 && q.get(3) === 2,
    "HPKE_SUITE_REQUIRED",
  );
}
export function segment(
  b: Uint8Array,
  id: string,
  index: number,
  rate: number,
) {
  demand(b.length >= 100 && b.length <= 384098, "INVALID_SEGMENT");
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  demand(
    new TextDecoder().decode(b.slice(0, 4)) === "SWL1" && uuidAt(b, 4) === id &&
      v.getUint32(20) === index,
    "SEGMENT_BINDING",
  );
  demand(
    v.getUint32(24) === rate && b[28] === 1 && b[29] === 1 &&
      v.getUint32(42) === index,
    "SEGMENT_FORMAT",
  );
  const sampleCount = integer(v.getUint32(30), 1, 192000);
  demand(
    v.getUint32(78) === sampleCount * 2 + 16 &&
      b.length === 82 + sampleCount * 2 + 16,
    "SEGMENT_LENGTH",
  );
  return {
    sampleCount,
    byteLength: b.length,
    previousHash: hex(b.slice(46, 78)),
    noncePrefix: hex(b.slice(34, 42)),
  };
}
// Reject duplicate keys (including escaped equivalents), excess nesting and trailing input before schema validation.
export function strictJson(text: string): any {
  let i = 0;
  const ws = () => {
    while (/\s/.test(text[i] ?? "") && i < text.length) i++;
  };
  const str = () => {
    const start = i++;
    while (i < text.length) {
      if (text[i] === "\\") {
        i += 2;
        continue;
      }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i));
    }
    throw new ApiError(400, "INVALID_JSON");
  };
  const value = (depth = 0): any => {
    demand(depth <= 12, "INVALID_JSON", 400);
    ws();
    if (text[i] === '"') return str();
    if (text[i] === "{" || text[i] === "[") {
      const object = text[i++] === "{";
      const out: any = object ? Object.create(null) : [];
      const seen = new Set();
      ws();
      const end = object ? "}" : "]";
      if (text[i] === end) {
        i++;
        return out;
      }
      while (i < text.length) {
        ws();
        let key: string | undefined;
        if (object) {
          demand(text[i] === '"', "INVALID_JSON", 400);
          key = str();
          demand(!seen.has(key), "DUPLICATE_KEY", 400);
          seen.add(key);
          ws();
          demand(text[i++] === ":", "INVALID_JSON", 400);
        }
        const v = value(depth + 1);
        if (object) out[key!] = v;
        else out.push(v);
        ws();
        const c = text[i++];
        if (c === end) return out;
        demand(c === ",", "INVALID_JSON", 400);
      }
      throw new ApiError(400, "INVALID_JSON");
    }
    const token =
      /^(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        text.slice(i),
      );
    demand(token, "INVALID_JSON", 400);
    i += token[0].length;
    return JSON.parse(token[0]);
  };
  try {
    const result = value();
    ws();
    demand(i === text.length, "INVALID_JSON", 400);
    return result;
  } catch (e) {
    if (e instanceof ApiError) throw e;
    throw new ApiError(400, "INVALID_JSON");
  }
}
export function decodeLp(bytes: Uint8Array): Uint8Array[] {
  const result: Uint8Array[] = [];
  let offset = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  while (offset < bytes.length) {
    demand(offset + 4 <= bytes.length, "MALFORMED_LP");
    const n = view.getUint32(offset, false);
    offset += 4;
    demand(n <= 8192 && offset + n <= bytes.length, "MALFORMED_LP");
    result.push(bytes.subarray(offset, offset + n));
    offset += n;
  }
  return result;
}
export function encodeLp(domain: string, ...parts: Uint8Array[]): Uint8Array {
  const all = [new TextEncoder().encode(domain), ...parts];
  const total = all.reduce((acc, p) => acc + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const p of all) {
    demand(p.length <= 8192, "LP_FIELD_TOO_LARGE");
    view.setUint32(offset, p.length, false);
    offset += 4;
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
export function parseAction(bytes: Uint8Array): {
  action: string;
  recordingId: string;
  resourceId: string;
  deviceId: string;
  policyHash: string;
  objectHash: string;
  issuedAt: number;
  expiresAt: number;
  nonce: string;
} {
  const f = decodeLp(bytes);
  demand(f.length === 10, "MALFORMED_ACTION");
  demand(
    new TextDecoder("ascii").decode(f[0]) === "swaralara/device-action/v1",
    "INVALID_DOMAIN",
  );
  const action = new TextDecoder("ascii").decode(f[1]);
  demand(
    ["share_ack", "request_cancel", "my_share", "release_list"].includes(
      action,
    ),
    "INVALID_ACTION",
  );
  demand(
    f[2].length === 16 && f[3].length === 16 && f[4].length === 16,
    "INVALID_UUID",
  );
  demand(f[5].length === 32 && f[6].length === 32, "INVALID_HASH");
  demand(f[7].length === 8 && f[8].length === 8, "INVALID_TIME");
  demand(f[9].length === 16, "INVALID_NONCE");
  const v7 = new DataView(f[7].buffer, f[7].byteOffset, 8);
  const v8 = new DataView(f[8].buffer, f[8].byteOffset, 8);
  const issuedAt = Number(v7.getBigInt64(0, false));
  const expiresAt = Number(v8.getBigInt64(0, false));
  const now = Date.now();
  demand(
    issuedAt > 0 && expiresAt > issuedAt && expiresAt - issuedAt <= 900000,
    "EXPIRED_ACTION",
  );
  demand(issuedAt <= now + 30000 && now < expiresAt, "EXPIRED_ACTION");
  return {
    action,
    recordingId: uuidAt(f[2], 0),
    resourceId: uuidAt(f[3], 0),
    deviceId: uuidAt(f[4], 0),
    policyHash: hex(f[5]),
    objectHash: hex(f[6]),
    issuedAt,
    expiresAt,
    nonce: uuidAt(f[9], 0),
  };
}
