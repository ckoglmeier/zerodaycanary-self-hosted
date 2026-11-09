'use client';
import { useEffect } from 'react';
import { usePathname } from 'next/navigation';
import type { PostHog } from 'posthog-js';
import { analyticsEnabled, analyticsPage, siteAnalyticsConfig, SITE_ACTIONS } from '@/lib/site-analytics';

let client: PostHog | undefined;
let initializing: Promise<PostHog> | undefined;
export function SiteAnalytics() {
  const pathname = usePathname();
  useEffect(() => {
    const token = process.env.NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN;
    const host = process.env.NEXT_PUBLIC_POSTHOG_HOST;
    if (!analyticsEnabled(process.env.NEXT_PUBLIC_POSTHOG_ENABLED, token, host) || !analyticsPage(pathname)) return;
    let active = true;
    const listener = (event: MouseEvent) => {
      const action = (event.target instanceof Element ? event.target.closest('[data-site-action]') : null)?.getAttribute('data-site-action');
      if (client && action && (SITE_ACTIONS as readonly string[]).includes(action) && analyticsPage(window.location.pathname)) client.capture('site_action',{ action });
    };
    initializing ??= import('posthog-js').then(({default: sdk}) => {
      if (!analyticsPage(window.location.pathname)) throw new Error('Analytics initialization cancelled outside public pages.');
      sdk.init(token!,siteAnalyticsConfig(host!,() => window.location.pathname));
      client = sdk;
      return sdk;
    });
    void initializing.then(sdk => {
      if (!active || !analyticsPage(window.location.pathname)) return;
      sdk.capture('$pageview');
      document.addEventListener('click',listener);
    }).catch(() => { initializing = undefined; }); // Analytics must never block the app.
    return () => { active = false; document.removeEventListener('click',listener); };
  },[pathname]);
  return null;
}
