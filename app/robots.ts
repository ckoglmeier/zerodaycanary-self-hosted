import type { MetadataRoute } from 'next';
import { isPreview, PUBLIC_ORIGIN } from '@/lib/discovery';

export default function robots(): MetadataRoute.Robots {
  if (isPreview()) return { rules: { userAgent: '*', disallow: '/' } };
  const privatePaths = ['/systems', '/developer', '/requests', '/reviews', '/reports', '/host/', '/billing', '/operator', '/account', '/auth', '/login', '/api/app/', '/api/host/', '/api/v1/developer/', '/api/operator/', '/api/cron/'];
  return {
    rules: [
      { userAgent: '*', allow: '/', disallow: privatePaths },
      { userAgent: ['OAI-SearchBot', 'Claude-SearchBot', 'Claude-User', 'ChatGPT-User'], allow: '/', disallow: privatePaths },
      // Keep training separate from search and user-initiated retrieval.
      { userAgent: ['GPTBot', 'ClaudeBot'], disallow: '/' },
    ],
    sitemap: `${PUBLIC_ORIGIN}/sitemap.xml`,
  };
}
