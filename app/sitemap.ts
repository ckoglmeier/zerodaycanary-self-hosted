import { connection } from 'next/server';
import type { MetadataRoute } from 'next';
import { allAdvisories } from '@/lib/catalog';
import { isPreview, PUBLIC_PAGES, publicUrl } from '@/lib/discovery';
export const revalidate = 300;
export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  await connection();
  if (isPreview()) return [];
  const records = await allAdvisories();
  return [
    ...PUBLIC_PAGES.map(path => ({ url: publicUrl(path) })),
    ...records.map(r => ({ url: publicUrl(`/advisory/${r.id}`), lastModified: r.updated_at })),
  ];
}
