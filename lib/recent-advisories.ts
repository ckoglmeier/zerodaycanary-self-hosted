import type { AdvisoryRecord } from "@/intel/schema";

// A catalog edit must not make an old disclosure appear newly published. Unknown
// publication dates follow dated records; revision dates remain explicitly labeled.
export function recentAdvisories(records: AdvisoryRecord[], limit = 6): AdvisoryRecord[] {
  const timestamp = (value: string | null) => value && Number.isFinite(Date.parse(value)) ? Date.parse(value) : -Infinity;
  return records.filter((record) => record.status === "published").sort((a, b) => {
    const aDate = timestamp(a.published_at);
    const bDate = timestamp(b.published_at);
    if (aDate !== bDate) return aDate > bDate ? -1 : 1;
    const aUpdated = timestamp(a.updated_at);
    const bUpdated = timestamp(b.updated_at);
    if (aUpdated !== bUpdated) return aUpdated > bUpdated ? -1 : 1;
    return a.id.localeCompare(b.id);
  }).slice(0, Math.max(0, limit));
}

// Vendor disclosure dates are often date-only. Do not invent a midnight
// publication time by displaying them as full observation timestamps.
export function disclosureDate(value: string | null): string | null {
  if (!value || !Number.isFinite(Date.parse(value))) return null;
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeZone: "UTC" }).format(new Date(value));
}
