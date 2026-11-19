// Test-only Supabase protocol fixture. NOT a replacement for Supabase Auth/Storage in deployment.
import { createServer } from "node:http";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { database } from "./harness.ts";
import { identity } from "./fixtures.ts";
import { makeApi } from "../functions/api/router.ts";
import { supabasePorts } from "../functions/api/supabase-adapter.ts";
import { trustProof } from "../functions/api/protocol.ts";

export async function startContractServer(port = 0, publicOrigin?: string) {
  const db = await database();
  const secret = randomBytes(32),
    password = randomBytes(24).toString("base64url");
  const service = randomBytes(32).toString("base64url"),
    key = "local-contract-fixture-public";
  const users = new Map<string, any>();
  const refresh = new Map<string, string>();
  const objects = new Map<string, Uint8Array>();
  const owner = await identity(),
    holder = await identity(),
    outsider = await identity();
  let failRead = false;
  for (
    const [email, d] of [["owner@test.local", owner], [
      "holder@test.local",
      holder,
    ], ["outsider@test.local", outsider]] as const
  ) {
    users.set(email, d);
    await db.query("insert into auth.users values($1)", [d.userId]);
  }
  const encode = (value: any) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  const signed = (payload: any) => {
    const b = `${encode({ alg: "HS256", typ: "JWT" })}.${encode(payload)}`;
    return `${b}.${createHmac("sha256", secret).update(b).digest("base64url")}`;
  };
  const checked = (token: string) => {
    try {
      const [a, b, c] = token.split(".");
      const expected = createHmac("sha256", secret).update(`${a}.${b}`)
        .digest();
      const actual = Buffer.from(c, "base64url");
      if (
        actual.length !== expected.length || !timingSafeEqual(expected, actual)
      ) return null;
      const p = JSON.parse(Buffer.from(b, "base64url").toString());
      return p.exp > Date.now() / 1000 ? p : null;
    } catch {
      return null;
    }
  };
  const issue = (id: string, lifetime = 3600) => {
    const rt = randomBytes(24).toString("base64url");
    refresh.set(rt, id);
    return {
      access_token: signed({
        sub: id,
        exp: Math.floor(Date.now() / 1000) + lifetime,
        aud: "authenticated",
      }),
      refresh_token: rt,
      expires_in: lifetime,
      token_type: "bearer",
      user: {
        id,
        aud: "authenticated",
        role: "authenticated",
        email: "fixture@test.local",
      },
    };
  };
  let origin = "", api: (request: Request) => Promise<Response>;
  const reply = (res: any, status: number, body: any) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url!, origin);
      let total = 0;
      const chunks: Buffer[] = [];
      for await (const part of req) {
        total += part.length;
        if (total > 1_048_576) {
          reply(res, 413, { error: "TOO_LARGE" });
          return;
        }
        chunks.push(part);
      }
      const bytes = Buffer.concat(chunks),
        body = bytes.length
          ? JSON.parse(
            req.headers["content-type"]?.startsWith("application/json")
              ? bytes.toString()
              : "{}",
          )
          : {};
      const auth = req.headers.authorization ?? "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      const actor = checked(token);
      if (url.pathname === "/auth/v1/token") {
        if (url.searchParams.get("grant_type") === "refresh_token") {
          const id = refresh.get(body.refresh_token);
          if (!id) {
            return reply(res, 401, { error_code: "refresh_token_not_found" });
          }
          refresh.delete(body.refresh_token);
          return reply(res, 200, issue(id));
        }
        const d = users.get(body.email);
        if (!d || body.password !== password) {
          return reply(res, 400, { error_code: "invalid_credentials" });
        }
        return reply(res, 200, issue(d.userId));
      }
      if (url.pathname === "/auth/v1/user") {
        return reply(
          res,
          actor ? 200 : 401,
          actor
            ? {
              id: actor.sub,
              aud: "authenticated",
              role: "authenticated",
              email: "fixture@test.local",
            }
            : { error: "Invalid JWT" },
        );
      }
      if (url.pathname === "/rest/v1/rpc/swl_m2") {
        if (token !== service) {
          return reply(res, 403, { message: "service only" });
        }
        try {
          const r = await db.query("select swl_m2($1,$2,$3::jsonb) as result", [
            body.p_actor,
            body.p_action,
            JSON.stringify(body.p),
          ]);
          return reply(res, 200, r.rows[0].result);
        } catch (e: any) {
          return reply(res, 400, { code: e.code, message: e.message });
        }
      }
      if (url.pathname.startsWith("/storage/v1/")) {
        const tail = url.pathname.slice("/storage/v1".length);
        const m =
          /^\/object\/(?:(upload\/sign|sign|authenticated)\/)?(swl-recordings\/.+)$/
            .exec(tail);
        if (!m) return reply(res, 404, { error: "not found" });
        const mode = m[1] ?? "authenticated", path = m[2];
        if (req.method === "POST") {
          if (token !== service) {
            return reply(res, 403, { error: "service only" });
          }
          const cap = signed({
            path,
            method: mode === "upload/sign" ? "PUT" : "GET",
            exp: Math.floor(Date.now() / 1000) +
              (mode === "upload/sign" ? 7200 : 60),
          });
          const relative = `/object/${mode}/${path}?token=${cap}`;
          return reply(
            res,
            200,
            mode === "upload/sign"
              ? { url: relative }
              : { signedURL: relative },
          );
        }
        if (mode === "authenticated") {
          if (token !== service) {
            return reply(res, 403, { error: "service only" });
          }
          if (failRead) {
            failRead = false;
            return reply(res, 503, { error: "simulated interruption" });
          }
        } else {
          const cap = checked(url.searchParams.get("token") ?? "");
          if (!cap || cap.path !== path || cap.method !== req.method) {
            return reply(res, 403, { error: "Invalid capability" });
          }
        }
        if (req.method === "PUT") {
          if (objects.has(path)) {
            return reply(res, 409, { error: "already exists" });
          }
          if (bytes.length > 384098) return reply(res, 413, { error: "size" });
          objects.set(path, new Uint8Array(bytes));
          return reply(res, 200, { Key: path });
        }
        const data = objects.get(path);
        if (!data) {
          return reply(res, 404, {
            error: "Object not found",
            statusCode: 404,
          });
        }
        res.writeHead(200, { "content-type": "application/octet-stream" });
        res.end(data);
        return;
      }
      if (url.pathname.startsWith("/__test__/")) {
        if (!actor) return reply(res, 401, { error: "auth required" });
        if (url.pathname === "/__test__/interrupt") {
          failRead = true;
          return reply(res, 200, { ok: true });
        }
        if (url.pathname === "/__test__/pair") {
          const call = async (jwt: string, path: string, p: any) => {
            const response = await api(
              new Request(`${origin}/functions/v1/api${path}`, {
                method: "POST",
                headers: {
                  authorization: `Bearer ${jwt}`,
                  "content-type": "application/json",
                },
                body: JSON.stringify(p),
              }),
            );
            const result = await response.json();
            if (!response.ok) throw Error(JSON.stringify(result));
            return result.data;
          };
          const htoken = issue(holder.userId).access_token;
          await call(htoken, "/bootstrap", { displayName: "Holder test" });
          await call(htoken, "/devices", holder.data);
          const i = await call(token, "/trust/invitations", {
            deviceId: body.ownerDeviceId,
          });
          const link = await call(htoken, "/trust/accept", {
            deviceId: holder.id,
            token: i.token,
          });
          await call(htoken, `/trust/${link.id}/confirm`, {
            deviceId: holder.id,
            signatureBase64: holder.signature(trustProof(link.id, holder.id)),
          });
          return reply(res, 200, {
            data: { linkId: link.id, holderUserId: holder.userId },
            requestId: crypto.randomUUID(),
          });
        }
        if (url.pathname === "/__test__/counts") {
          return reply(res, 200, {
            data: {
              objects: objects.size,
              segments: (await db.query(
                "select count(*)::int as n from recording_segments s join recordings r on r.id=s.recording_id where r.owner_user_id=$1",
                [actor.sub],
              )).rows[0].n,
            },
            requestId: crypto.randomUUID(),
          });
        }
      }
      const response = await api(
        new Request(`${origin}${req.url}`, {
          method: req.method,
          headers: req.headers as any,
          body: bytes.length ? bytes : undefined,
        }),
      );
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch {
      reply(res, 500, { error: "Contract fixture failure" });
    }
  });
  await new Promise<void>((resolve) =>
    server.listen(port, "127.0.0.1", resolve)
  );
  const address = server.address() as any;
  origin = `http://127.0.0.1:${address.port}`;
  api = makeApi(supabasePorts(origin, key, service, publicOrigin ?? origin));
  return {
    origin,
    key,
    password,
    owner,
    holder,
    outsider,
    db,
    objects,
    issue,
    api,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      await db.close();
    },
  };
}
if (process.argv[1]?.endsWith("contract-server.ts")) {
  const port = Number(process.env.SWL_FIXTURE_PORT ?? "8787");
  const fixture = await startContractServer(
    port,
    process.env.SWL_FIXTURE_PUBLIC_ORIGIN ?? `http://127.0.0.1:${port}`,
  );
  await mkdir(".tools", { recursive: true });
  await writeFile(
    process.env.SWL_FIXTURE_STATE_FILE ?? ".tools/m2-contract-fixture.json",
    JSON.stringify({
      password: fixture.password,
      key: fixture.key,
      origin: fixture.origin,
    }),
  );
  console.log(
    `TEST-ONLY contract fixture listening on port ${port}; runtime credentials are in an ignored local state file`,
  );
  process.on("SIGINT", () => {
    fixture.close().then(() => process.exit(0));
  });
}
