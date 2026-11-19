import {
  ApiError,
  b64,
  bytesHex,
  decodePolicy,
  demand,
  deviceProof,
  encodeLp,
  fields,
  hash,
  hex,
  integer,
  label,
  parseAction,
  segment,
  sha,
  strictJson,
  trustProof,
  unbase64,
  uuid,
  uuidAt,
  validateHpkePublic,
  verify,
} from "./protocol.ts";
import { bindEnvelope, live, lpShape, number64 } from "./m3-validation.ts";
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
        return respond({ status: "ok", version: "m3" });
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
      if (path === "/m3/recordings" && method === "GET") {
        const deviceId = uuid(
          new URL(request.url).searchParams.get("deviceId"),
        );
        return respond(await call("m3_recordings", { deviceId }));
      }
      match = /^\/recordings\/([^/]+)(?:\/(.*))?$/.exec(path);
      if (match) {
        const id = uuid(match[1]), tail = match[2] ?? "";
        if (!tail && method === "GET") {
          return respond(await call("detail", { id }));
        }
        if (tail === "members" && method === "GET") {
          return respond(await call("m3_members", { id }));
        }
        if (tail === "acknowledgments" && method === "GET") {
          return respond(await call("m3_acknowledgments", { id }));
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
        if (tail === "share-envelopes" && method === "POST") {
          await rate("upload");
          const rec = await call("owner", { id });
          const d = await call("device", { id: rec.source_device_id });
          const p = await body(["envelopes"]);
          demand(Array.isArray(p.envelopes) && p.envelopes.length > 0);
          for (const env of p.envelopes) {
            fields(env, [
              "shareIndex",
              "holderDeviceId",
              "schemeVersion",
              "envelopeCiphertextBase64",
              "contextBytesBase64",
              "ownerSignatureBase64",
              "ciphertextSha256",
            ]);
            demand(env.schemeVersion === "shamir-bc-gf256-v1");
            integer(env.shareIndex, 1, 3);
            uuid(env.holderDeviceId);
            hash(env.ciphertextSha256);
            const cipher = unbase64(env.envelopeCiphertextBase64, 16384);
            demand(await sha(cipher) === env.ciphertextSha256);
            const ctx = unbase64(env.contextBytesBase64, 4096);
            bindEnvelope(
              ctx,
              id,
              rec.policy_snapshot_hash,
              env.shareIndex,
              env.holderDeviceId,
            );
            const sigPayload = encodeLp(
              "swaralara/share-envelope-signature/v1",
              ctx,
              bytesHex(env.ciphertextSha256),
            );
            await verify(
              unbase64(d.signingBase64.replace(/\s/g, "")),
              sigPayload,
              unbase64(env.ownerSignatureBase64, 80),
            );
          }
          return respond(
            await call("envelopes_create", {
              recordingId: id,
              envelopes: p.envelopes,
            }),
          );
        }
        if (tail === "my-share" && method === "GET") {
          const deviceId = uuid(
            new URL(request.url).searchParams.get("deviceId"),
          );
          const actionBase64 = new URL(request.url).searchParams.get(
            "actionBase64",
          );
          const signatureBase64 = new URL(request.url).searchParams.get(
            "signatureBase64",
          );
          demand(actionBase64 && signatureBase64, "DEVICE_SIGNATURE_REQUIRED");
          {
            const actBytes = unbase64(actionBase64, 1024);
            const act = parseAction(actBytes);
            demand(
              act.action === "my_share" && act.recordingId === id &&
                act.deviceId === deviceId,
            );
            const dev = await call("device", { id: deviceId });
            await verify(
              unbase64(dev.signingBase64.replace(/\s/g, "")),
              actBytes,
              unbase64(signatureBase64, 80),
            );
          }
          const envelope = await call("my_share", {
            recordingId: id,
            deviceId,
          });
          const action = parseAction(unbase64(actionBase64, 1024));
          const policyHash = await sha(
            unbase64(envelope.policySnapshotBase64.replace(/\s/g, ""), 512),
          );
          demand(
            action.resourceId === id && action.policyHash === policyHash &&
              action.objectHash === policyHash,
            "CONTEXT_BINDING",
          );
          return respond(envelope);
        }
        if (tail === "my-share/ack" && method === "POST") {
          await rate("request");
          const p = await body([
            "deviceId",
            "actionBytesBase64",
            "signatureBase64",
          ]);
          uuid(p.deviceId);
          const actBytes = unbase64(p.actionBytesBase64, 1024);
          const act = parseAction(actBytes);
          demand(
            act.action === "share_ack" && act.recordingId === id &&
              act.deviceId === p.deviceId,
          );
          const dev = await call("device", { id: p.deviceId });
          const envelope = await call("my_share", {
            recordingId: id,
            deviceId: p.deviceId,
          });
          demand(
            act.resourceId === id &&
              act.policyHash ===
                await sha(
                  unbase64(
                    envelope.policySnapshotBase64.replace(/\s/g, ""),
                    512,
                  ),
                ) &&
              act.objectHash === envelope.ciphertextSha256,
            "CONTEXT_BINDING",
          );
          await verify(
            unbase64(dev.signingBase64.replace(/\s/g, "")),
            actBytes,
            unbase64(p.signatureBase64, 80),
          );
          return respond(
            await call("my_share_ack", {
              recordingId: id,
              deviceId: p.deviceId,
              ackSignatureBase64: p.signatureBase64,
              actionBytesBase64: p.actionBytesBase64,
            }),
          );
        }
        // M4 workflows: signed final manifest and encrypted notes
        if (["manifest", "notes"].includes(tail)) {
          await call("owner", { id });
          throw new ApiError(501, "MILESTONE_NOT_IMPLEMENTED");
        }
      }
      if (path === "/access-requests" && method === "POST") {
        await rate("request");
        const p = await body([
          "id",
          "recordingId",
          "requesterDeviceId",
          "requestHpkePublicKeysetBase64",
          "requestBytesBase64",
          "requestSignatureBase64",
          "expiresAt",
        ]);
        uuid(p.id);
        uuid(p.recordingId);
        uuid(p.requesterDeviceId);
        demand(
          typeof p.expiresAt === "string" &&
            Number.isFinite(Date.parse(p.expiresAt)),
        );
        const reqBytes = unbase64(p.requestBytesBase64, 2048);
        const parts = lpShape(reqBytes, "swaralara/key-request/v1", [
          16,
          16,
          16,
          32,
          32,
          8,
          8,
          16,
        ]);
        const reqFields = [new Uint8Array(), ...parts];
        demand(uuidAt(reqFields[1], 0) === p.id);
        demand(uuidAt(reqFields[2], 0) === p.recordingId);
        demand(uuidAt(reqFields[3], 0) === p.requesterDeviceId);
        const rec = await call("detail", { id: p.recordingId });
        const publicKey = unbase64(p.requestHpkePublicKeysetBase64, 4096);
        const publicSet = strictJson(
          new TextDecoder("utf-8", { fatal: true }).decode(publicKey),
        );
        demand(Array.isArray(publicSet.key) && publicSet.key.length === 1);
        const publicEntry = publicSet.key[0];
        demand(
          publicEntry.status === "ENABLED" &&
            publicEntry.outputPrefixType === "TINK" &&
            publicEntry.keyId === publicSet.primaryKeyId &&
            publicEntry.keyData?.typeUrl ===
              "type.googleapis.com/google.crypto.tink.HpkePublicKey" &&
            publicEntry.keyData?.keyMaterialType === "ASYMMETRIC_PUBLIC",
        );
        validateHpkePublic(unbase64(publicEntry.keyData.value, 128));
        demand(
          hex(reqFields[4]) ===
            await sha(
              unbase64(rec.policySnapshotBase64.replace(/\s/g, ""), 512),
            ),
          "CONTEXT_BINDING",
        );
        demand(hex(reqFields[5]) === await sha(publicKey), "CONTEXT_BINDING");
        const issuedAt = number64(reqFields[6]),
          expiresAt = number64(reqFields[7]);
        live(issuedAt, expiresAt);
        demand(expiresAt === Date.parse(p.expiresAt), "CONTEXT_BINDING");
        const dev = await call("device", { id: p.requesterDeviceId });
        await verify(
          unbase64(dev.signingBase64.replace(/\s/g, "")),
          reqBytes,
          unbase64(p.requestSignatureBase64, 80),
        );
        return respond(
          await call("request_create", {
            ...p,
            requestNonce: uuidAt(reqFields[8], 0),
          }),
        );
      }
      if (path === "/access-requests" && method === "GET") {
        return respond(await call("request_list"));
      }
      match = /^\/access-requests\/([^/]+)(?:\/(.*))?$/.exec(path);
      if (match) {
        const id = uuid(match[1]), tail = match[2] ?? "";
        if (!tail && method === "GET") {
          return respond(await call("request_detail", { id }));
        }
        if (tail === "decision" && method === "POST") {
          await rate("decision");
          const p = await body([
            "decision",
            "holderDeviceId",
            "shareIndex",
            "signedDecisionBase64",
            "decisionSignatureBase64",
            "releaseCiphertextBase64",
            "contextBytesBase64",
            "holderSignatureBase64",
            "ciphertextSha256",
          ]);
          demand(["approve", "deny"].includes(p.decision));
          uuid(p.holderDeviceId);
          integer(p.shareIndex, 1, 3);
          const dev = await call("device", { id: p.holderDeviceId });
          const decBytes = unbase64(p.signedDecisionBase64, 2048);
          demand(
            new TextDecoder().decode(decBytes) ===
              `${p.decision}:${id}:${p.shareIndex}`,
            "DECISION_BINDING",
          );
          await verify(
            unbase64(dev.signingBase64.replace(/\s/g, "")),
            decBytes,
            unbase64(p.decisionSignatureBase64, 80),
          );
          if (p.decision === "approve") {
            demand(
              p.releaseCiphertextBase64 && p.contextBytesBase64 &&
                p.holderSignatureBase64 && p.ciphertextSha256,
            );
            hash(p.ciphertextSha256);
            const relCipher = unbase64(p.releaseCiphertextBase64, 16384);
            demand(await sha(relCipher) === p.ciphertextSha256);
            const ctxBytes = unbase64(p.contextBytesBase64, 4096);
            const req = await call("request_detail", { id });
            const f = lpShape(ctxBytes, "swaralara/share-release/v1", [
              16,
              16,
              16,
              32,
              32,
              4,
              16,
              8,
              8,
              16,
            ]);
            const requestRaw = unbase64(
              req.requestBytesBase64.replace(/\s/g, ""),
              2048,
            );
            const requestFields = lpShape(
              requestRaw,
              "swaralara/key-request/v1",
              [16, 16, 16, 32, 32, 8, 8, 16],
            );
            demand(
              uuidAt(f[0], 0) === id && uuidAt(f[1], 0) === req.recordingId &&
                uuidAt(f[2], 0) === req.requesterDeviceId &&
                hex(f[3]) === hex(requestFields[3]) &&
                hex(f[4]) === await sha(requestRaw) &&
                new DataView(f[5].buffer, f[5].byteOffset, 4).getUint32(0) ===
                  p.shareIndex &&
                uuidAt(f[6], 0) === p.holderDeviceId &&
                number64(f[7]) === Date.parse(req.expiresAt),
              "CONTEXT_BINDING",
            );
            demand(
              number64(f[8]) >= number64(requestFields[5]) - 30000 &&
                number64(f[8]) <= Date.now() + 30000,
              "EXPIRED_ACTION",
            );
            const sigPayload = encodeLp(
              "swaralara/share-release-signature/v1",
              ctxBytes,
              bytesHex(p.ciphertextSha256),
            );
            await verify(
              unbase64(dev.signingBase64.replace(/\s/g, "")),
              sigPayload,
              unbase64(p.holderSignatureBase64, 80),
            );
          }
          return respond(await call("request_decision", { id, ...p }));
        }
        if (
          ["releases", "recording", "segments"].includes(tail) &&
          method === "GET"
        ) {
          const req = await call("request_detail", { id });
          demand(Date.now() < Date.parse(req.expiresAt), "EXPIRED", 410);
          demand(req.state === "ready", "CONFLICT", 409);
          const query = new URL(request.url).searchParams;
          const actBytes = unbase64(query.get("actionBase64"), 1024);
          const act = parseAction(actBytes);
          demand(
            act.action === "release_list" &&
              act.recordingId === req.recordingId && act.resourceId === id &&
              act.deviceId === req.requesterDeviceId &&
              act.policyHash ===
                await sha(
                  unbase64(req.policySnapshotBase64.replace(/\s/g, ""), 512),
                ) &&
              act.objectHash ===
                await sha(
                  unbase64(req.requestBytesBase64.replace(/\s/g, ""), 2048),
                ) &&
              act.expiresAt === Date.parse(req.expiresAt),
            "CONTEXT_BINDING",
          );
          const dev = await call("device", { id: act.deviceId });
          await verify(
            unbase64(dev.signingBase64.replace(/\s/g, "")),
            actBytes,
            unbase64(query.get("signatureBase64"), 80),
          );
          if (tail === "recording") {
            return respond(await call("recovery_recording", { id }));
          }
          if (tail === "segments") {
            await rate("read");
            const offset = integer(
              Number(query.get("offset") ?? "0"),
              0,
              100000,
            );
            const rows = await call("recovery_segments", { id, offset });
            const items = [];
            for (const row of rows) {
              items.push({
                index: Number(row.segment_index),
                objectHash: row.object_sha256,
                previousHash: row.previous_sha256,
                byteLength: row.byte_length,
                sampleCount: row.sample_count,
                readUrl: await deps.storage.signRead(row.storage_path),
              });
            }
            return respond(items);
          }
          return respond(await call("request_releases", { id }));
        }
        if (tail === "cancel" && method === "POST") {
          await rate("request");
          const p = await body([
            "deviceId",
            "actionBytesBase64",
            "signatureBase64",
          ]);
          uuid(p.deviceId);
          const actBytes = unbase64(p.actionBytesBase64, 1024);
          const act = parseAction(actBytes);
          const req = await call("request_detail", { id });
          demand(
            act.recordingId === req.recordingId &&
              act.deviceId === req.requesterDeviceId &&
              act.policyHash ===
                await sha(
                  unbase64(req.policySnapshotBase64.replace(/\s/g, ""), 512),
                ) &&
              act.objectHash ===
                await sha(
                  unbase64(req.requestBytesBase64.replace(/\s/g, ""), 2048),
                ) &&
              act.expiresAt === Date.parse(req.expiresAt),
            "CONTEXT_BINDING",
          );
          demand(
            act.action === "request_cancel" && act.resourceId === id &&
              act.deviceId === p.deviceId,
          );
          const dev = await call("device", { id: p.deviceId });
          await verify(
            unbase64(dev.signingBase64.replace(/\s/g, "")),
            actBytes,
            unbase64(p.signatureBase64, 80),
          );
          return respond(await call("request_cancel", { id, ...p }));
        }
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
