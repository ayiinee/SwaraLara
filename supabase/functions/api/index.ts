import { makeApi } from "./router.ts";
import { supabasePorts } from "./supabase-adapter.ts";

const required = (name: string) => {
  const value = Deno.env.get(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};
// Never print env, JWT, service credentials, or signed URLs.
Deno.serve(
  makeApi(
    supabasePorts(
      required("SUPABASE_URL"),
      required("SUPABASE_ANON_KEY"),
      required("SUPABASE_SERVICE_ROLE_KEY"),
      Deno.env.get("SWL_PUBLIC_SUPABASE_URL"),
    ),
  ),
);
