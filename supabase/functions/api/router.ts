import {
  ApiError,
  b64,
  decodePolicy,
  demand,
  deviceProof,
  fields,
  hash,
  bindingBytes,
  integer,
  label,
  segment,
  sha,
  strictJson,
  trustProof,
  unbase64,
  uuid,
  validateHpkePublic,
  verify,
} from "./protocol.ts";
export interface Database {
  call(actor: string, action: string, p?: any): Promise<any>;
}
export interface Storage {
  signUpload(path: string): Promise<string>;
  read(path: string): Promise<Uint8Array | null>;
  signRead(path: string): Promise<string>;
}
export interface Auth {
  getUser(token: string): Promise<{ id: string } | null>;
}
export function makeApi(deps: { db: Database; storage: Storage; auth: Auth }) {
  return async (request: Request): Promise<Response> => {
    const requestId = crypto.randomUUID();
    const respond = (data: any, status = 200) =>
      Response.json({ data, requestId }, {
        status,
        headers: { "Cache-Control": "no-store" },
      });
    try {
      const path = new URL(request.url).pathname.replace(
        /^\/functions\/v1\/api/,
        "",
      );
      const method = request.method;
      if (method === "GET" && path === "/health") {
        return respond({ status: "ok", version: "m2" });
      }
      const bearer = request.headers.get("authorization");
      demand(
        bearer?.startsWith("Bearer ") && bearer.length < 8192,
        "UNAUTHENTICATED",
        401,
      );
      const actor = await deps.auth.getUser(bearer!.slice(7));
      demand(actor, "UNAUTHENTICATED", 401);
      uuid(actor.id);
      const call = (action: string, p?: any) =>
        deps.db.call(actor!.id, action, p);
      const rate = async (operation: string) =>
        demand(
          (await call("rate", { operation })).allowed,
          "RATE_LIMITED",
          429,
        );
      const body = async (names: string[]) => {
        demand(
          (request.headers.get("content-type") ?? "").split(";")[0] ===
            "application/json",
          "CONTENT_TYPE",
          415,
        );
        const reader = request.body?.getReader();
        demand(reader, "INVALID_JSON", 400);
        let size = 0;
        const parts: Uint8Array[] = [];
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            demand(size <= 16384, "BODY_TOO_LARGE", 413);
            parts.push(value);
          }
        } finally {
          await reader.cancel();
        }
        const b = new Uint8Array(size);
        let at = 0;
        for (const p of parts) {
          b.set(p, at);
          at += p.length;
        }
        let text: string;
        try {
          text = new TextDecoder("utf-8", { fatal: true }).decode(b);
        } catch {
          throw new ApiError(400, "INVALID_JSON");
        }
        return fields(strictJson(text), names);
      };
      if (path === "/bootstrap" && method === "POST") {
        const p = await body(["displayName"]);
        return respond(
          await call("bootstrap", { displayName: label(p.displayName) }),
        );
      }
      if (path === "/devices/me" && method === "GET") {
        return respond(await call("devices"));
      }
      if (path === "/devices" && method === "POST") {
        await rate("device");
        const p = await body([
          "id",
          "label",
          "hpkePublicKeysetBase64",
          "signingPublicSpkiBase64",
          "proofSignatureBase64",
        ]);
        uuid(p.id);
        label(p.label);
        const hpke = unbase64(p.hpkePublicKeysetBase64);
        const spki = unbase64(p.signingPublicSpkiBase64, 200);
        // Public Tink JSON only; never accept a private keyset as device registration.
        const keyset = strictJson(new TextDecoder().decode(hpke));
        fields(keyset, ["primaryKeyId", "key"]);
        demand(Array.isArray(keyset.key) && keyset.key.length === 1);
        const entry = fields(keyset.key[0], [
          "keyData",
          "status",
          "keyId",
          "outputPrefixType",
        ]);
        const kd = fields(entry.keyData, [
          "typeUrl",
          "value",
          "keyMaterialType",
        ]);
        demand(
          kd.keyMaterialType === "ASYMMETRIC_PUBLIC" &&
            kd.typeUrl ===
              "type.googleapis.com/google.crypto.tink.HpkePublicKey" &&
            entry.status === "ENABLED" && entry.keyId === keyset.primaryKeyId &&
            entry.outputPrefixType === "TINK",
          "HPKE_PUBLIC_KEY_REQUIRED",
        );
        validateHpkePublic(unbase64(kd.value, 512));
        await verify(
          spki,
          await deviceProof(p.id, hpke, spki),
          unbase64(p.proofSignatureBase64, 80),
        );
        return respond(
          await call("device_create", {
            ...p,
            hpkeFingerprint: await sha(hpke),
            signingFingerprint: await sha(spki),
          }),
        );
      }
      if (path === "/trust/invitations" && method === "POST") {
        await rate("invitation");
        const p = await body(["deviceId"]);
        uuid(p.deviceId);
        const token = b64(crypto.getRandomValues(new Uint8Array(32)))
          .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
        return respond({
          ...await call("invite", {
            deviceId: p.deviceId,
            id: crypto.randomUUID(),
            tokenHash: await sha(new TextEncoder().encode(token)),
          }),
          token,
        });
      }
      if (path === "/trust/accept" && method === "POST") {
        await rate("accept");
        const p = await body(["deviceId", "token"]);
        uuid(p.deviceId);
        demand(
          typeof p.token === "string" && /^[A-Za-z0-9_-]{43}$/.test(p.token),
        );
        return respond(
          await call("accept", {
            deviceId: p.deviceId,
            linkId: crypto.randomUUID(),
            tokenHash: await sha(new TextEncoder().encode(p.token)),
          }),
        );
      }
      if (path === "/trust" && method === "GET") {
        return respond(await call("trust"));
      }
      let match = /^\/trust\/([^/]+)\/confirm$/.exec(path);
      if (match && method === "POST") {
        const id = uuid(match[1]);
        const p = await body(["deviceId", "signatureBase64"]);
        uuid(p.deviceId);
        await call("link", { id });
        const d = await call("device", { id: p.deviceId });
        await verify(
          unbase64(d.signingBase64.replace(/\s/g, "")),
          trustProof(id, p.deviceId),
          unbase64(p.signatureBase64, 80),
        );
        return respond(await call("confirm", { id, deviceId: p.deviceId }));
      }
      if (path === "/recordings" && method === "POST") {
        await rate("recording");
        const p = await body([
          "id",
          "sourceDeviceId",
          "kind",
          "policyCode",
          "sampleRate",
          "channels",
          "pcmEncoding",
          "startedAtDevice",
          "captureState",
          "totalSegments",
          "totalSamples",
          "policySnapshotBase64",
          "policySignatureBase64",
        ]);
        uuid(p.id);
        uuid(p.sourceDeviceId);
        demand(["live_event", "retrospective"].includes(p.kind));
        demand(
          ["owner_required_2of2", "recovery_2of3"].includes(p.policyCode),
          "DEMO_CLOUD_FORBIDDEN",
        );
        demand(
          [16000, 44100, 48000].includes(p.sampleRate) && p.channels === 1 &&
            p.pcmEncoding === "pcm16le",
        );
        demand(["sealed", "interrupted"].includes(p.captureState));
        integer(p.totalSegments, 1, 100000);
        integer(p.totalSamples, 1, 192000 * p.totalSegments);
        demand(
          typeof p.startedAtDevice === "string" &&
            Number.isFinite(Date.parse(p.startedAtDevice)),
        );
        p.startedAtDevice = new Date(p.startedAtDevice).toISOString();
        const snapshot = unbase64(p.policySnapshotBase64, 4096);
        const policy = decodePolicy(snapshot);
        demand(
          policy.id === p.id && policy.ownerUserId === actor.id &&
            policy.sourceDeviceId === p.sourceDeviceId &&
            policy.policyCode === p.policyCode,
          "POLICY_BINDING",
        );
        const d = await call("device", { id: p.sourceDeviceId });
        await verify(
          unbase64(d.signingBase64.replace(/\s/g, "")),
          snapshot,
          unbase64(p.policySignatureBase64, 80),
        );
        const canonical = Object.fromEntries(
          Object.keys(p).sort().map((k) => [k, p[k]]),
        );
        return respond(
          await call("register", {
            ...p,
            members: policy.members,
            policySnapshotHash: await sha(snapshot),
            registrationHash: await sha(
              new TextEncoder().encode(JSON.stringify(canonical)),
            ),
          }),
        );
      }
      if (path === "/recordings" && method === "GET") {
        const cursor = new URL(request.url).searchParams.get("before");
        if (cursor) uuid(cursor);
        const items = await call("list", { before: cursor });
        return respond({
          items,
          nextCursor: items.length === 50 ? items.at(-1).id : null,
        });
      }
      match = /^\/recordings\/([^/]+)(?:\/(.*))?$/.exec(path);
      if (match) {
        const id = uuid(match[1]), tail = match[2] ?? "";
        if (!tail && method === "GET") {
          return respond(await call("detail", { id }));
        }
        if (tail === "audit" && method === "GET") {
          return respond(await call("audit", { id }));
        }
        if (tail === "segments" && method === "GET") {
          return respond(await call("segments", { id }));
        }
        if (
          (tail === "segments/upload-url" || tail === "segments/commit") &&
          method === "POST"
        ) {
          await rate("upload");
          const p = await body(["index", "objectHash"]);
          integer(p.index, 0, 4294967295);
          hash(p.objectHash);
          const r = await call("owner", { id });
          demand(p.index < r.total_segments);
          const storagePath = `${actor.id}/${id}/segments/${
            String(p.index).padStart(10, "0")
          }.swseg`;
          if (tail === "segments/upload-url") {
            const existing = (await call("segments", { id })).find((s: any) =>
              Number(s.segment_index) === p.index
            );
            if (existing) {
              demand(existing.object_sha256 === p.objectHash, "CONFLICT", 409);
              return respond({ alreadyCommitted: true });
            }
            return respond({
              uploadUrl: await deps.storage.signUpload(storagePath),
              storagePath,
              alreadyCommitted: false,
            });
          }
          const bytes = await deps.storage.read(storagePath);
          demand(bytes, "OBJECT_NOT_UPLOADED", 409);
          const metadata = segment(bytes!, id, p.index, r.sample_rate);
          const objectHash = await sha(bytes!);
          demand(objectHash === p.objectHash, "OBJECT_HASH_MISMATCH", 409);
          return respond(
            await call("commit", {
              id,
              index: p.index,
              storagePath,
              objectHash,
              ...metadata,
            }),
          );
        }
        const read = /^segments\/(\d+)\/read-url$/.exec(tail);
        if (read && method === "POST") {
          await rate("read");
          await call("owner", { id });
          const index = integer(Number(read[1]), 0, 4294967295);
          const item = (await call("segments", { id })).find((s: any) =>
            Number(s.segment_index) === index
          );
          demand(item, "NOT_FOUND", 404);
          return respond({
            readUrl: await deps.storage.signRead(item.storage_path),
            expiresInSeconds: 60,
          });
        }
        if (tail === "manifest" && method === "PUT") {
          await rate("manifest");
          const p = await body(["manifestBase64", "signatureBase64", "idempotencyKey"]);
          const manifest = unbase64(p.manifestBase64, 1048576);
          const signature = unbase64(p.signatureBase64, 80);
          demand(typeof p.idempotencyKey === "string" && p.idempotencyKey.length <= 128);
          await call("owner", { id });
          const d = await call("device", { id: (await call("owner", { id })).source_device_id });
          await verify(unbase64(d.signingBase64), bindingBytes("SWM1", [id, manifest]), signature);
          return respond(await call("manifest", { id, manifestBase64: p.manifestBase64, signatureBase64: p.signatureBase64, manifestHash: await sha(manifest), idempotencyKey: p.idempotencyKey }));
        }
        if (tail === "share-envelopes" && method === "POST") {
          const p = await body(["shareIndex", "holderDeviceId", "ciphertextBase64", "contextBase64", "signatureBase64", "idempotencyKey"]);
          integer(p.shareIndex, 1, 3); uuid(p.holderDeviceId);
          unbase64(p.ciphertextBase64, 16384); unbase64(p.contextBase64, 4096); unbase64(p.signatureBase64, 80);
          return respond(await call("share_envelope", { id, ...p }));
        }
        if (tail === "my-share" && method === "GET") return respond(await call("my_share", { id }));
        if (tail === "my-share/ack" && method === "POST") {
          const p = await body(["envelopeHash", "signatureBase64", "idempotencyKey"]);
          hash(p.envelopeHash); unbase64(p.signatureBase64, 80);
          return respond(await call("share_ack", { id, ...p }));
        }
      }
      if (path === "/access-requests" && method === "POST") {
        const p = await body(["id", "recordingId", "requesterDeviceId", "requestHpkePublicKeysetBase64", "requestBytesBase64", "signatureBase64", "expiresAt", "idempotencyKey"]);
        uuid(p.id); uuid(p.recordingId); uuid(p.requesterDeviceId); unbase64(p.requestHpkePublicKeysetBase64, 8192); unbase64(p.requestBytesBase64, 4096); unbase64(p.signatureBase64, 80);
        return respond(await call("access_request", p));
      }
      if (path === "/access-requests" && method === "GET") return respond(await call("access_requests"));
      const access = /^\/access-requests\/([^/]+)(?:\/(.*))?$/.exec(path);
      if (access) {
        const requestId = uuid(access[1]), tail = access[2] ?? "";
        if (tail === "decision" && method === "POST") {
          const p = await body(["decision", "shareIndex", "releaseCiphertextBase64", "contextBase64", "signatureBase64", "idempotencyKey"]);
          demand(["approve", "deny"].includes(p.decision)); integer(p.shareIndex, 1, 3); unbase64(p.releaseCiphertextBase64, 16384); unbase64(p.contextBase64, 4096); unbase64(p.signatureBase64, 80);
          return respond(await call("access_decision", { id: requestId, ...p }));
        }
        if (tail === "releases" && method === "GET") return respond(await call("access_releases", { id: requestId }));
        if (tail === "complete" && method === "POST") return respond(await call("access_complete", { id: requestId, ...(await body(["resultBase64", "signatureBase64"])) }));
        if (tail === "cancel" && method === "POST") return respond(await call("access_cancel", { id: requestId }));
      }
      throw new ApiError(404, "NOT_FOUND");
    } catch (error) {
      const e = error instanceof ApiError
        ? error
        : new ApiError(500, "INTERNAL");
      return Response.json({
        error: {
          code: e.code,
          message: e.status >= 500
            ? "Layanan belum tersedia."
            : "Operasi tidak tersedia atau tidak valid.",
        },
        requestId,
      }, { status: e.status, headers: { "Cache-Control": "no-store" } });
    }
  };
}
