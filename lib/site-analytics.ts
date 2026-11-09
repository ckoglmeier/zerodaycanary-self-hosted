import type { CaptureResult, PostHogConfig } from 'posthog-js';
import { PUBLIC_ORIGIN, PUBLIC_PAGES } from './discovery';

export const SITE_ACTIONS = ['builder_start','buyer_start','browse_alerts','view_api','view_pricing','download_skill'] as const;
export type SiteAction = typeof SITE_ACTIONS[number];
export function analyticsPage(pathname: string): string | null {
  // Never send query strings, fragments, arbitrary IDs or private invitation paths.
  const path = pathname.split(/[?#]/,1)[0];
  if (/^\/advisory\/[^/]+$/.test(path)) return '/advisory/:id';
  return (PUBLIC_PAGES as readonly string[]).includes(path) ? path : null;
}
export function analyticsEnabled(enabled?: string, token?: string, host?: string) {
  return enabled === 'true' && !!token && /^phc_[A-Za-z0-9_-]+$/.test(token) && ['https://us.i.posthog.com','https://eu.i.posthog.com'].includes(host ?? '');
}
export function sanitizeSiteEvent(event: CaptureResult, currentPath: string): CaptureResult | null {
  const page = analyticsPage(currentPath);
  if (!page || !['$pageview','site_action'].includes(event.event)) return null;
  const properties = event.properties;
  const action = properties.action;
  if (event.event === 'site_action' && !(SITE_ACTIONS as readonly string[]).includes(action)) return null;
  // Explicit allowlist strips SDK URL/referrer/UTM, user/profile and DOM properties.
  return { uuid: event.uuid, event: event.event, timestamp: event.timestamp, properties: {
    // PostHog builds its ingestion api_key from this public project token after
    // before_send. Keep it while discarding user, URL and profile properties.
    ...(typeof properties.token === 'string' && /^phc_[A-Za-z0-9_-]+$/.test(properties.token) ? {token:properties.token} : {}),
    distinct_id: properties.distinct_id,
    $current_url: `${PUBLIC_ORIGIN}${page === '/' ? '' : page}`,
    $pathname: page,
    $host: new URL(PUBLIC_ORIGIN).host,
    $process_person_profile: false,
    $ip: null,
    ...(event.event === 'site_action' ? { action } : {}),
  } };
}
export function siteAnalyticsConfig(host: string, currentPath: () => string): Partial<PostHogConfig> {
  return {
    api_host: host, defaults: '2026-08-30', persistence: 'memory',
    autocapture: false, capture_pageview: false, capture_pageleave: false,
    disable_session_recording: true, enable_recording_console_log: false,
    capture_performance: false, capture_exceptions: false, capture_heatmaps: false,
    capture_dead_clicks: false, disable_surveys: true, disable_external_dependency_loading: true,
    advanced_disable_flags: true, person_profiles: 'never', ip: false, respect_dnt: true,
    before_send: event => sanitizeSiteEvent(event,currentPath()),
  };
}
