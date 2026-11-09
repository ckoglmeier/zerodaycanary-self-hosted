import { publicMetadata } from '@/lib/discovery';
import { Feed } from "@/components/feed";
import { feedData } from "@/lib/public-pages";

// Cached at the CDN; publication revalidates immediately, and a failed refresh keeps
// serving the last good page.
export const revalidate = 300;

export const metadata = { ...publicMetadata('/advisories', "Zero Day Canary", "Vulnerability alerts and evidence-backed answers for your apps and vendors."), title: "Vulnerability alerts", description: "Reviewed vulnerability alerts with exploitation evidence, affected versions and primary sources. The same records are available as a public API." };

export default async function KnownExploited() {
  const d = await feedData("priority");
  return <Feed view="priority" {...d} />;
}
