import { PGlite } from "@electric-sql/pglite";
import { readFile } from "node:fs/promises";
import { ApiError } from "../functions/api/protocol.ts";
import { makeApi } from "../functions/api/router.ts";

export async function database() {
  const db = new PGlite();
  await db.exec(
    `create role anon; create role authenticated; create role service_role bypassrls;
  create schema auth; create table auth.users(id uuid primary key);
  create schema storage; create table storage.buckets(id text primary key,name text,public boolean,file_size_limit bigint,allowed_mime_types text[]);
  create table storage.objects(id uuid primary key default gen_random_uuid(),bucket_id text references storage.buckets(id),name text);
  alter table storage.objects enable row level security;
  grant usage on schema public,storage to anon,authenticated,service_role;
  grant all on storage.objects to anon,authenticated;
  create policy unrelated_project_policy on storage.objects for all to anon,authenticated using(true) with check(true);`,
  );
  for (
    const file of [
      "202611180001_foundation.sql",
      "202611180002_m2_transactions.sql",
    ]
  ) {
    await db.exec(
      await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8"),
    );
  }
  return db;
}
export function ports(db: any) {
  const users = new Map<string, string>();
  const objects = new Map<string, Uint8Array>();
  let interrupted = false;
  const api = makeApi({
    auth: {
      async getUser(token) {
        const id = users.get(token);
        return id ? { id } : null;
      },
    },
    db: {
      async call(actor, action, p = {}) {
        try {
          const result = await db.query(
            "select public.swl_m2($1,$2,$3::jsonb) as result",
            [actor, action, JSON.stringify(p)],
          );
          return result.rows[0].result;
        } catch (e: any) {
          const codes: Record<string, number> = {
            NOT_FOUND: 404,
            CONFLICT: 409,
            INVALID: 422,
            EXPIRED: 410,
            FINGERPRINT_CHANGED: 409,
          };
          throw new ApiError(codes[e.message] ?? 500, e.message);
        }
      },
    },
    storage: {
      async signUpload(path) {
        return `https://storage.test/upload/${path}`;
      },
      async read(path) {
        if (interrupted) {
          interrupted = false;
          throw new ApiError(503, "STORAGE_UNAVAILABLE");
        }
        return objects.get(path) ?? null;
      },
      async signRead(path) {
        return `https://storage.test/read/${path}`;
      },
    },
  });
  const request = async (
    actorToken: string,
    path: string,
    method = "GET",
    body?: any,
  ) => {
    const res = await api(
      new Request(`http://127.0.0.1/functions/v1/api${path}`, {
        method,
        headers: {
          authorization: `Bearer ${actorToken}`,
          "content-type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
    return { status: res.status, ...await res.json() };
  };
  return {
    api,
    users,
    objects,
    request,
    interruptStorage: () => {
      interrupted = true;
    },
  };
}
