// Refreshes the Supabase session cookie on navigation. Authorization itself happens in
// each page and route handler; this only keeps tokens fresh.
import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

export async function proxy(request: NextRequest) {
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-canary-path", request.nextUrl.pathname);
  requestHeaders.set("x-canary-return-to", request.nextUrl.pathname + request.nextUrl.search);
  let response = NextResponse.next({ request: { headers: requestHeaders } });
  const sb = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {
    cookies: {
      getAll: () => request.cookies.getAll(),
      setAll: (list) => {
        for (const { name, value } of list) request.cookies.set(name, value);
        requestHeaders.set("cookie", request.cookies.toString());
        response = NextResponse.next({ request: { headers: requestHeaders } });
        for (const { name, value, options } of list) response.cookies.set(name, value, options);
      },
    },
  });
  await sb.auth.getUser();
  return response;
}

export const config = {
  // Public catalog pages and API stay cookie-free so the CDN can cache them.
  matcher: ["/systems/:path*", "/requests/:path*", "/reviews/:path*", "/reports/:path*", "/developer/:path*", "/billing/:path*", "/account", "/operator/:path*", "/auth/:path*", "/login", "/api/app/:path*"],
};
