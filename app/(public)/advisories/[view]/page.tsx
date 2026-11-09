import { notFound } from "next/navigation";
import { Feed, type FeedView } from "@/components/feed";
import { feedData } from "@/lib/public-pages";
import { publicMetadata } from '@/lib/discovery';

export async function generateMetadata({ params }: { params: Promise<{ view: string }> }) {
  const { view } = await params;
  return publicMetadata(`/advisories/${view}`, view === 'exploited' ? 'Alerts with exploitation evidence' : view === 'poc' ? 'Alerts with public proof of concept' : 'All reviewed vulnerability alerts', 'Reviewed alerts with evidence sources, affected versions and explicit uncertainty.');
}
export const revalidate = 300;
export const dynamicParams = false;
export function generateStaticParams() {
  return [{ view: "poc" }, { view: "all" }, {view:"exploited"}];
}

export default async function AdvisoryView({ params }: { params: Promise<{ view: string }> }) {
  const { view } = await params;
  const v: FeedView | null = view === "exploited" ? "known_exploited" : view === "poc" ? "public_poc" : view === "all" ? "all" : null;
  if (!v) notFound();
  const d = await feedData(v);
  return <Feed view={v} {...d} />;
}
