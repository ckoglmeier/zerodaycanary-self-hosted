import { headers } from "next/headers";
import { requireViewer } from "@/lib/auth";
import { Footer, Header } from "@/components/shell";
import { userQ } from "@/lib/db";

export const dynamic = "force-dynamic";
export const metadata = { robots: { index: false, follow: false } };

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const path = (await headers()).get("x-canary-return-to") ?? "/systems";
  const v = await requireViewer(path);
  const [workspace] = await userQ<{name:string}>(v,"select name from workspaces where id=$1",[v.workspaceId]);
  return (
    <>
      <Header viewer={{email:v.email,organization:workspace?.name||"Your workspace",isOperator:v.isOperator}} />
      <main id="main-content" tabIndex={-1} className="container">{children}</main>
      <Footer />
    </>
  );
}
