import type { Metadata } from 'next';

// Public identity is independent of an ephemeral preview URL or local environment.
export const PUBLIC_ORIGIN = (process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000').replace(/\/$/, '');
export const PRODUCT_DESCRIPTION = 'Zero Day Canary helps local businesses and nonprofits check possible exposure to major software vulnerabilities, get answers from their developers, and track what needs fixing.';
export const PUBLIC_PAGES = ['/', '/about', '/advisories', '/advisories/all', '/advisories/feed', '/advisories/exploited', '/advisories/poc', '/pricing', '/docs/api', '/docs/skill', '/for-buyers', '/for-builders', '/for-education', '/contact'] as const;
export const isPreview = () => process.env.VERCEL_ENV === 'preview';
export const publicUrl = (path: string) => `${PUBLIC_ORIGIN}${path === '/' ? '' : path}`;
export function publicMetadata(path: string, title: string, description: string): Metadata {
  return { title: path === '/' ? { absolute: title } : title, description, alternates: { canonical: publicUrl(path) }, openGraph: { title, description, url: publicUrl(path), siteName: 'Zero Day Canary', type: 'website', images: [{ url: `${PUBLIC_ORIGIN}/brand/canary-logo.png`, alt: 'Zero Day Canary' }] }, twitter: { card: 'summary', title, description, images: [`${PUBLIC_ORIGIN}/brand/canary-logo.png`] } };
}
export function jsonLd(value: unknown) {
  // Catalog content is untrusted text, including inside a script element.
  return JSON.stringify(value).replace(/</g, '\\u003c');
}
