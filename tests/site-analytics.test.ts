import { describe, it, expect } from 'vitest';
import { analyticsEnabled, analyticsPage, sanitizeSiteEvent, siteAnalyticsConfig } from '@/lib/site-analytics';
const sample = { uuid:'fixture-uuid',event:'$pageview',properties:{distinct_id:'temporary-browser-id',$current_url:'https://example.com/requests/private?token=secret',email:'private@example.com',source:'secret', $referrer:'https://private.example/records?token=secret'},$set:{email:'private@example.com'} };
describe('public-site analytics boundary',() => {
  it('requires explicit activation, a public project token and a known ingestion host',() => {
    expect(analyticsEnabled(undefined,'phc_example','https://us.i.posthog.com')).toBe(false);
    expect(analyticsEnabled('true',undefined,'https://us.i.posthog.com')).toBe(false);
    expect(analyticsEnabled('true','phx_personal_key','https://us.i.posthog.com')).toBe(false);
    expect(analyticsEnabled('true','phc_example','https://untrusted.invalid')).toBe(false);
    expect(analyticsEnabled('true','phc_example','https://eu.i.posthog.com')).toBe(true);
  });
  it('allows only public routes, strips query/hash and groups advisory IDs',() => {
    expect(analyticsPage('/docs/skill?token=secret#private')).toBe('/docs/skill');
    expect(analyticsPage('/advisory/private-looking-id')).toBe('/advisory/:id');
    for(const path of ['/systems/secret','/developer','/reports/secret','/reviews/secret','/requests/secret','/host/token','/login','/billing','/operator','/not-a-page']) expect(analyticsPage(path)).toBeNull();
  });
  it('strips default URL, referrer, source, profile and form properties',() => {
    const event = sanitizeSiteEvent(sample,'/docs/skill?email=secret');
    expect(event).toEqual({uuid:'fixture-uuid',event:'$pageview',timestamp:undefined,properties:{distinct_id:'temporary-browser-id',$current_url:'http://localhost:3000/docs/skill',$pathname:'/docs/skill',$host:'localhost:3000',$process_person_profile:false,$ip:null}});
    expect(JSON.stringify(event)).not.toContain('secret');expect(event).not.toHaveProperty('$set');
  });
  it('blocks private-page events, arbitrary actions and SDK automatic event types',() => {
    expect(sanitizeSiteEvent(sample,'/reports/123')).toBeNull();
    expect(sanitizeSiteEvent({...sample,event:'$identify'},'/')).toBeNull();
    expect(sanitizeSiteEvent({...sample,event:'site_action',properties:{action:'anything private'}},'/')).toBeNull();
    expect(sanitizeSiteEvent({...sample,event:'site_action',properties:{action:'download_skill',text:'secret'}},'/docs/skill')?.properties.action).toBe('download_skill');
  });
  it('retains the public project token needed by PostHog ingestion after before_send',()=>{
    const event=sanitizeSiteEvent({...sample,properties:{...sample.properties,token:'phc_public_project'}},'/');
    expect(event?.properties.token).toBe('phc_public_project');
    expect(JSON.stringify(event)).not.toContain('secret');
    expect(sanitizeSiteEvent({...sample,properties:{...sample.properties,token:'phx_personal_key'}},'/')?.properties).not.toHaveProperty('token');
  });
  it('turns off replay, autocapture, profiles, storage persistence, flags and auxiliary capture',() => {
    expect(siteAnalyticsConfig('https://us.i.posthog.com',()=>'/')).toMatchObject({persistence:'memory',autocapture:false,capture_pageview:false,capture_pageleave:false,disable_session_recording:true,capture_exceptions:false,disable_external_dependency_loading:true,advanced_disable_flags:true,person_profiles:'never',ip:false,respect_dnt:true});
  });
});
