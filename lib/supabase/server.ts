import "server-only";
import { createServerClient } from "@supabase/ssr";
import { createClient } from "@supabase/supabase-js";
import { cookies } from "next/headers";
import { env } from "../env";

// Request-scoped client acting as the signed-in user: all reads go through RLS.
export async function userClient() {
  const store = await cookies();
  return createServerClient(env.supabaseUrl(), env.supabaseAnon(), {
    cookies: {
      getAll: () => store.getAll(),
      setAll: (list) => {
        try {
          for (const { name, value, options } of list) store.set(name, value, options);
        } catch {
          // Called from a Server Component; the proxy refreshes cookies instead.
        }
      },
    },
  });
}

// Anonymous client for public catalog reads (no cookies, cacheable).
export function publicClient() {
  return createClient(env.supabaseUrl(), env.supabaseAnon(), { auth: { persistSession: false } });
}
