import { decodeLp, demand, hex, uuidAt } from "./protocol.ts";

export function lpShape(bytes: Uint8Array, domain: string, sizes: number[]) {
  const f = decodeLp(bytes);
  demand(
    f.length === sizes.length + 1 && new TextDecoder().decode(f[0]) === domain,
    "CONTEXT_BINDING",
  );
  demand(sizes.every((n, i) => f[i + 1].length === n), "CONTEXT_LENGTH");
  return f.slice(1);
}
export function number64(b: Uint8Array) {
  demand(b.length === 8);
  const n = Number(new DataView(b.buffer, b.byteOffset, 8).getBigInt64(0));
  demand(Number.isSafeInteger(n));
  return n;
}
export function live(issued: number, expires: number) {
  const now = Date.now();
  demand(
    issued > 0 && expires > issued && expires - issued <= 900000 &&
      issued <= now + 30000 && now < expires,
    "EXPIRED_ACTION",
  );
}
export function bindEnvelope(
  raw: Uint8Array,
  id: string,
  policy: string,
  index: number,
  holder: string,
) {
  const f = lpShape(raw, "swaralara/share-envelope/v1", [16, 32, 4, 16]);
  demand(
    uuidAt(f[0], 0) === id && hex(f[1]) === policy &&
      new DataView(f[2].buffer, f[2].byteOffset, 4).getUint32(0) === index &&
      uuidAt(f[3], 0) === holder,
    "CONTEXT_BINDING",
  );
}
