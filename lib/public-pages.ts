import "server-only";
import { allAdvisories, catalogMeta } from "./catalog";
import {sourceCount} from './source-feed';
import type { FeedView } from "@/components/feed";

export async function feedData(view: FeedView) {
  const [records, featured, meta,sourceTotal] = await Promise.all([allAdvisories({ includeInactive: true }), allAdvisories({featuredOnly:true}), catalogMeta(),sourceCount()]);
  const active = records.filter((r) => r.status === "published");
  const counts = {
    priority: featured.length,
    known_exploited: active.filter((r) => r.exploitation.category === "known_exploited").length,
    public_poc: active.filter((r) => r.exploitation.category === "public_poc").length,
    all: records.length,
  };
  const shown = view === "priority" ? featured : view === "all" ? records : active.filter((r) => r.exploitation.category === view);
  return { records: shown, meta, counts,sourceTotal };
}
