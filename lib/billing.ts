import "server-only";
// Team subscriptions bill one workspace unit. Legacy subscriptions retain per-system billing.
// The server owns price and quantity. Monitoring becomes active only when a verified
// webhook reports a subscription in good standing that covers the system.
import Stripe from "stripe";
import type {PoolClient} from "pg";
import {monitoringState} from "./monitoring-plan";
import { createHash,randomUUID } from "node:crypto";
import { env } from "./env";
import { HttpError } from "./auth";
import { q, one, tx, databaseSchema } from "./db";

export const PRICE_LOOKUP_KEY = "zdc_workspace_team_monthly";
export const LEGACY_PRICE_LOOKUP_KEY = "zdc_monitored_system_monthly";
export const NONPROFIT_LOOKUP_KEY = "zdc_nonprofit_workspace_team_monthly";
const LEGACY_NONPROFIT_LOOKUP_KEY = "zdc_nonprofit_monitored_system_monthly";
// Documented proration policy: Stripe's standard proration on quantity changes,
// invoiced on the next regular invoice. No custom credits.
// Operator-issued invoice credits are separately audited in billing_credits.
export const PRORATION: Stripe.SubscriptionUpdateParams.ProrationBehavior = "create_prorations";

let _stripe: Stripe | null = null;
export const CHECKOUT_BRANDING = {display_name:'Zero Day Canary',background_color:'#F7F8F6',button_color:'#172B32',border_style:'rounded',icon:{type:'url',url:env.siteUrl()+'/brand/canary-160.png'}} as const;
export function stripe(): Stripe {
  if (!_stripe) _stripe = new Stripe(env.stripeKey());
  return _stripe;
}

export type PriceInfo = { id: string; unit_amount: number; currency: string; interval: string; livemode: boolean };
const priceCache = new Map<boolean,{at:number;p:PriceInfo}>();

// The displayed price is always read from the configured Stripe price, never hard-coded.
export async function getPrice(nonprofit=false): Promise<PriceInfo | null> {
  const cached=priceCache.get(nonprofit);
  if (cached && Date.now() - cached.at < 5 * 60_000) return cached.p;
  const list = await stripe().prices.list({ lookup_keys: [nonprofit?NONPROFIT_LOOKUP_KEY:PRICE_LOOKUP_KEY], active: true, limit: 1 });
  const p = list.data[0];
  if (!p || p.unit_amount == null || !p.recurring) return null;
  if(p.currency!=='usd'||p.recurring.interval!=='month'||p.recurring.interval_count!==1||p.recurring.usage_type!=='licensed'||p.billing_scheme!=='per_unit'||p.unit_amount!==(nonprofit?2900:4900))throw new Error('Configure a fixed USD monthly workspace price.');
  const value={id:p.id,unit_amount:p.unit_amount,currency:p.currency,interval:p.recurring.interval,livemode:p.livemode};
  priceCache.set(nonprofit,{at:Date.now(),p:value});
  return value;
}

export async function workspacePrice(workspaceId:string){const ws=await one<{nonprofit:boolean}>('select nonprofit from workspaces where id=$1',[workspaceId]);return getPrice(Boolean(ws?.nonprofit));}

export function money(cents: number, currency = "usd") {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: currency.toUpperCase() }).format(cents / 100);
}

type Sub = { workspace_id: string; stripe_subscription_id: string | null; status: string; quantity: number; current_period_end: Date | null; cancel_at_period_end: boolean; billing_model: "per_system" | "workspace" };

export async function subscriptionFor(workspaceId: string): Promise<Sub | null> {
  return one<Sub>("select * from subscriptions where workspace_id = $1", [workspaceId]);
}

const GOOD = new Set(["active", "trialing"]);
const TROUBLED = new Set(["past_due", "unpaid", "incomplete", "paused"]);

export async function desiredQuantity(workspaceId: string): Promise<number> {
  const r = await one<{ n: string }>(
    "select count(*) n from systems where workspace_id = $1 and removed_at is null and monitoring in ('pending_payment','active','payment_issue')",
    [workspaceId],
  );
  return Number(r?.n ?? 0);
}

export async function ensureCustomer(workspaceId: string, email: string, client?:PoolClient): Promise<string> {
  const run=async (c:PoolClient)=>{
    await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))",[`billing-customer:${workspaceId}`]);
    const ws=(await c.query<{stripe_customer_id:string|null}>('select stripe_customer_id from workspaces where id=$1 for update',[workspaceId])).rows[0];
    if(!ws)throw new HttpError(404,'Workspace not found.');
    if(ws.stripe_customer_id){try{const existing=await stripe().customers.retrieve(ws.stripe_customer_id);if(!existing.deleted)return existing.id;}catch(e){if((e as {code?:string}).code!=='resource_missing')throw e;}}
    // A customer deleted in Stripe must not be resurrected by an old cached
    // idempotency response. The workspace lock prevents concurrent replacements.
    const customer=await stripe().customers.create({email,metadata:{workspace_id:workspaceId}},{idempotencyKey:`cust-${workspaceId}-${randomUUID()}`});
    await c.query('update workspaces set stripe_customer_id=$2 where id=$1',[workspaceId,customer.id]);
    return customer.id;
  };
  return client?run(client):tx(run);
}

// Shared single-system entry; the first is free and Team always bills one unit.
export async function requestMonitoring(workspaceId:string,email:string,systemId:string) {
  const ws=await one<{owner_id:string}>('select owner_id from workspaces where id=$1',[workspaceId]);
  if(!ws)throw new HttpError(404,'Workspace not found.');
  return startMonitoringCart(workspaceId,ws.owner_id,email,[systemId],false,randomUUID());
}

export async function startMonitoringCart(workspaceId:string,userId:string,email:string,systemIds:string[],nonprofit:boolean,clientKey:string){
  if(!systemIds.length||systemIds.length>25||systemIds.some(id=>typeof id!=='string'||!/^[0-9a-f-]{36}$/.test(id))||new Set(systemIds).size!==systemIds.length||!/^[0-9a-f-]{36}$/.test(clientKey))throw new HttpError(400,'Choose 1–25 systems. For more than 25, contact us.');
  return tx(async c=>{
    await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))",[`billing:${workspaceId}`]);
    const owned=(await c.query('select id from systems where workspace_id=$1 and id=any($2::uuid[]) and removed_at is null',[workspaceId,systemIds])).rows;
    if(owned.length!==systemIds.length)throw new HttpError(404,'A selected system is not available in your workspace.');
    const sub=(await c.query<Sub>('select * from subscriptions where workspace_id=$1',[workspaceId])).rows[0];
    const existing=Boolean(sub?.stripe_subscription_id&&(GOOD.has(sub.status)||TROUBLED.has(sub.status)));
    if(existing&&sub.billing_model!=='workspace')throw new HttpError(409,'Your existing per-system plan is unchanged. Contact us to move to workspace pricing.');
    // Preserve committed monitoring; replace abandoned, unpaid cart selections.
    await c.query("update systems set monitoring='none' where workspace_id=$1 and monitoring='pending_payment' and not(id=any($2::uuid[]))",[workspaceId,systemIds]);
    await c.query("update systems set monitoring='pending_payment',monitoring_requested_at=coalesce(monitoring_requested_at,now()) where workspace_id=$1 and id=any($2::uuid[]) and removed_at is null and monitoring in ('none','paused')",[workspaceId,systemIds]);
    const rows=(await c.query<{id:string;monitoring:string}>("select id,monitoring from systems where workspace_id=$1 and removed_at is null and monitoring in ('pending_payment','active','payment_issue') order by monitoring_requested_at nulls last,created_at,id",[workspaceId])).rows;
    if(rows.length>25)throw new HttpError(400,'Team includes up to 25 systems. Contact us for a larger portfolio.');
    if(existing){
      // Re-read provider state before granting a newly requested paid slot.
      const current=await stripe().subscriptions.retrieve(sub.stripe_subscription_id!);
      const price=await getPrice(current.metadata.nonprofit==='true');
      if(!price||current.items.data.length!==1||current.items.data[0].price.id!==price.id||current.items.data[0].quantity!==1)throw new HttpError(409,'Your subscription needs review. Open Billing.');
      const paid=GOOD.has(current.status);
      for(const [i,row]of rows.entries())await c.query('update systems set monitoring=$2 where id=$1',[row.id,i===0||paid?'active':'payment_issue']);
      return {checkoutUrl:null,quantity:rows.length};
    }
    if(rows.length===1){
      await c.query("update systems set monitoring='active' where id=$1",[rows[0].id]);
      // A previous unpaid upgrade must not remain payable after selecting Free.
      const ws=(await c.query<{stripe_customer_id:string|null}>('select stripe_customer_id from workspaces where id=$1',[workspaceId])).rows[0];
      if(ws?.stripe_customer_id){const open=await stripe().checkout.sessions.list({customer:ws.stripe_customer_id,status:'open',limit:100});for(const session of open.data)if(session.client_reference_id===workspaceId)await stripe().checkout.sessions.expire(session.id);}
      return {checkoutUrl:null,quantity:1};
    }
    const [price,standard]=await Promise.all([getPrice(nonprofit),getPrice()]);
    if(!price||!standard)throw new HttpError(400,'Team checkout is not configured yet. Your first system can be monitored free.');
    if(nonprofit&&price.unit_amount>standard.unit_amount)throw new HttpError(400,'The nonprofit discount is unavailable.');
    const customer=await ensureCustomer(workspaceId,email,c);
    // Checkout can complete before its webhook arrives. Never create a second
    // subscription while the provider already has a live one for this workspace.
    const providerSubscriptions=await stripe().subscriptions.list({customer,status:'all',limit:100});
    if(providerSubscriptions.data.some(s=>s.metadata.workspace_id===workspaceId&&!['canceled','incomplete_expired'].includes(s.status)))throw new HttpError(409,'Your subscription is being confirmed. Check Billing before trying another payment.');
    const intentKey=`workspace-${workspaceId}-${clientKey}-${createHash('sha256').update(JSON.stringify({systems:[...systemIds].sort(),price:price.id})).digest('hex').slice(0,16)}`;
    const open=await stripe().checkout.sessions.list({customer,status:'open',limit:100});
    const same=open.data.find(x=>x.client_reference_id===workspaceId&&x.metadata?.cart_key===intentKey);
    for(const session of open.data)if(session.client_reference_id===workspaceId&&session.id!==same?.id)await stripe().checkout.sessions.expire(session.id);
    // A checkout attempt also keeps one system free, even if payment is abandoned.
    await c.query("update systems set monitoring='active' where id=$1",[rows[0].id]);
    if(same)return {checkoutUrl:same.url,quantity:rows.length};
    const session=await stripe().checkout.sessions.create({branding_settings:CHECKOUT_BRANDING,mode:'subscription',customer,client_reference_id:workspaceId,line_items:[{price:price.id,quantity:1}],subscription_data:{metadata:{workspace_id:workspaceId,nonprofit:String(nonprofit),canary_schema:databaseSchema()}},metadata:{workspace_id:workspaceId,cart_key:intentKey,canary_schema:databaseSchema()},success_url:`${env.siteUrl()}/billing/confirm?session_id={CHECKOUT_SESSION_ID}`,cancel_url:`${env.siteUrl()}/billing/checkout?cancelled=1`});
    return {checkoutUrl:session.url,quantity:rows.length};
  });
}

async function setQuantity(subscriptionId: string, qty: number) {
  const s = await stripe().subscriptions.retrieve(subscriptionId);
  const item = s.items.data[0];
  if (qty <= 0) {
    // Nothing left to monitor: cancel at period end rather than refunding mid-period.
    if (!s.cancel_at_period_end) await stripe().subscriptions.update(subscriptionId, { cancel_at_period_end: true });
    return;
  }
  if (item.quantity !== qty || s.cancel_at_period_end)
    await stripe().subscriptions.update(subscriptionId, { items: [{ id: item.id, quantity: qty }], proration_behavior: PRORATION, cancel_at_period_end: false });
}

// Team pauses retain the subscription; legacy plans still adjust quantity.
export async function releaseMonitoring(workspaceId:string,systemId:string,action:"pause"|"remove"){
  await tx(async c=>{
    await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))",[`billing:${workspaceId}`]);
    if(action==='pause')await c.query("update systems set monitoring='paused' where id=$1 and workspace_id=$2 and monitoring<>'none'",[systemId,workspaceId]);
    else await c.query("update systems set removed_at=now(),monitoring='none' where id=$1 and workspace_id=$2",[systemId,workspaceId]);
    const sub=(await c.query<Sub>('select * from subscriptions where workspace_id=$1',[workspaceId])).rows[0];
    if(sub?.stripe_subscription_id&&sub.billing_model==='per_system'&&sub.status!=='canceled'){
      const count=(await c.query<{n:string}>("select count(*) n from systems where workspace_id=$1 and removed_at is null and monitoring in ('pending_payment','active','payment_issue')",[workspaceId])).rows[0];
      await setQuantity(sub.stripe_subscription_id,Number(count.n));
    }
    await c.query("insert into system_events(workspace_id,system_id,kind,detail) values($1,$2,$3,'{}')",[workspaceId,systemId,action==='pause'?'monitoring_paused':'system_removed']);
  });
  await reconcile(workspaceId);
}

export async function portalUrl(workspaceId: string): Promise<string | null> {
  const ws = await one<{ stripe_customer_id: string | null }>("select stripe_customer_id from workspaces where id = $1", [workspaceId]);
  if (!ws?.stripe_customer_id) return null;
  const sub=await subscriptionFor(workspaceId);
  let configuration:string|undefined;
  if(sub?.billing_model==='workspace'){
    configuration=process.env.STRIPE_WORKSPACE_PORTAL_CONFIGURATION;
    if(!configuration)throw new HttpError(503,'Team billing portal is not configured. Contact support.');
    const config=await stripe().billingPortal.configurations.retrieve(configuration);
    if(!config.active||!config.features.subscription_cancel.enabled||config.features.subscription_cancel.mode!=='at_period_end'||config.features.subscription_update.enabled)throw new HttpError(503,'Team billing portal configuration needs review.');
  }
  const s = await stripe().billingPortal.sessions.create({ customer: ws.stripe_customer_id, configuration, return_url: `${env.siteUrl()}/billing` });
  return s.url;
}

// ───────────── Webhook processing ─────────────

const SUB_EVENTS = new Set([
  "checkout.session.completed",
  "checkout.session.expired",
  "customer.subscription.created",
  "customer.subscription.updated",
  "customer.subscription.deleted",
  "customer.subscription.paused",
  "customer.subscription.resumed",
  "invoice.paid",
  "invoice.payment_failed",
]);

function subscriptionIdOf(event: Stripe.Event): string | null {
  const o = event.data.object as unknown as Record<string, unknown>;
  if (event.type.startsWith("customer.subscription.")) return o.id as string;
  if (event.type.startsWith("checkout.session.")) return (o.subscription as string) ?? null;
  if (event.type.startsWith("invoice.")) {
    const parent = o.parent as { subscription_details?: { subscription?: string } } | undefined;
    return (parent?.subscription_details?.subscription as string) ?? (o.subscription as string) ?? null;
  }
  return null;
}

// Idempotent: each event id is processed once. Out-of-order safe: the subscription is
// re-read from Stripe, so state reflects Stripe's current truth, not event order.
export async function handleStripeEvent(event: Stripe.Event): Promise<{ status: "processed" | "duplicate" | "ignored" }> {
  const fresh = await one<{ id: string }>(
    "insert into stripe_events (id, type, created) values ($1,$2,$3) on conflict (id) do nothing returning id",
    [event.id, event.type, event.created],
  );
  if (!fresh) {
    const prev = await one<{ processed_at: Date | null }>("select processed_at from stripe_events where id = $1", [event.id]);
    if (prev?.processed_at) return { status: "duplicate" };
  }
  try {
    if (!SUB_EVENTS.has(event.type)) {
      await q("update stripe_events set processed_at = now() where id = $1", [event.id]);
      return { status: "ignored" };
    }
    if (event.type === "checkout.session.expired") {
      // Abandoned checkout: requested-but-unpaid systems stay pending; nothing activates.
      await q("update stripe_events set processed_at = now() where id = $1", [event.id]);
      return { status: "processed" };
    }
    const subId = subscriptionIdOf(event);
    if (subId) await syncSubscription(subId, event.created);
    await q("update stripe_events set processed_at = now(), error = null where id = $1", [event.id]);
    return { status: "processed" };
  } catch (e) {
    await q("update stripe_events set error = $2 where id = $1", [event.id, (e as Error).message]);
    throw e;
  }
}

export async function syncSubscription(subscriptionId: string, eventCreated = Math.floor(Date.now() / 1000)) {
  // Locate the workspace, then serialize with carts and re-read Stripe after the
  // lock. A delayed event cannot overwrite a newer cart with a stale snapshot.
  const initial=await stripe().subscriptions.retrieve(subscriptionId);
  // Shared Stripe TEST accounts deliver every event to every registered endpoint.
  // Old untagged subscriptions belong to production; new preview subscriptions are tagged.
  if((initial.metadata?.canary_schema||'public')!==databaseSchema())return;
  const workspaceId=initial.metadata?.workspace_id;
  if(!workspaceId)throw new Error('Subscription has no workspace metadata.');
  await tx(async c=>{
    await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))",[`billing:${workspaceId}`]);
    const s=await stripe().subscriptions.retrieve(subscriptionId);
    const ws=(await c.query<{stripe_customer_id:string|null}>("select stripe_customer_id from workspaces where id=$1",[workspaceId])).rows[0];
    if(!ws||s.metadata.workspace_id!==workspaceId)throw new Error('Unknown workspace in subscription metadata.');
    const customer=typeof s.customer==='string'?s.customer:s.customer.id;
    if(ws.stripe_customer_id&&ws.stripe_customer_id!==customer)throw new Error('Subscription customer does not match workspace.');
    if(s.items.data.length!==1)throw new Error('Unexpected subscription structure.');
    const item=s.items.data[0];
    const [standard,nonprofit]=await Promise.all([getPrice(),getPrice(true)]);
    const actual=item.price.id;
    const legacy=await stripe().prices.list({lookup_keys:[LEGACY_PRICE_LOOKUP_KEY,LEGACY_NONPROFIT_LOOKUP_KEY],active:true,limit:10});
    const old=legacy.data.find(p=>p.id===actual);
    const model=old?'per_system':'workspace';
    if(!old&&![standard?.id,nonprofit?.id].includes(actual))throw new Error('Subscription price is not an approved monitoring rate.');
    if(model==='workspace'&&item.quantity!==1)throw new Error('Team requires exactly one workspace billing unit.');
    const discounted=actual===nonprofit?.id||old?.lookup_key===LEGACY_NONPROFIT_LOOKUP_KEY;
    if(discounted&&s.metadata.nonprofit!=='true')throw new Error('Nonprofit subscription lacks its attestation metadata.');
    const current=(await c.query<{stripe_subscription_id:string|null;status:string}>('select stripe_subscription_id,status from subscriptions where workspace_id=$1',[workspaceId])).rows[0];
    if(current?.stripe_subscription_id&&current.stripe_subscription_id!==s.id&&!['canceled','incomplete_expired'].includes(current.status))throw new Error('A different subscription already covers this workspace.');
    const periodEnd=(item as unknown as {current_period_end?:number}).current_period_end;
    // Portal cancellations may set an explicit cancel_at timestamp while leaving
    // cancel_at_period_end false. Retain the scheduled-cancellation notice in either form.
    const cancellationScheduled=Boolean(s.cancel_at_period_end||s.cancel_at);
    await c.query(`insert into subscriptions (workspace_id,stripe_subscription_id,status,quantity,current_period_end,cancel_at_period_end,stripe_event_created,billing_model,updated_at)
      values($1,$2,$3,$4,$5,$6,$7,$8,now()) on conflict(workspace_id) do update set stripe_subscription_id=excluded.stripe_subscription_id,status=excluded.status,billing_model=excluded.billing_model,quantity=excluded.quantity,current_period_end=excluded.current_period_end,cancel_at_period_end=excluded.cancel_at_period_end,stripe_event_created=greatest(subscriptions.stripe_event_created,excluded.stripe_event_created),updated_at=now()`,[workspaceId,s.id,s.status,item.quantity??0,periodEnd?new Date(periodEnd*1000):null,cancellationScheduled,eventCreated,model]);
    await c.query('update workspaces set stripe_customer_id=coalesce(stripe_customer_id,$2),nonprofit=$3 where id=$1',[workspaceId,customer,discounted]);
  });
  await reconcile(workspaceId);
}

// Applies the plan allowance and standing, oldest request first.
export async function reconcile(workspaceId:string){
  await tx(async c=>{
    await c.query("select pg_advisory_xact_lock(hashtextextended($1,0))",[`billing:${workspaceId}`]);
    const sub=(await c.query<Sub>('select * from subscriptions where workspace_id=$1',[workspaceId])).rows[0];
    const systems=(await c.query<{id:string;monitoring:string}>("select id,monitoring from systems where workspace_id=$1 and removed_at is null and monitoring in ('pending_payment','active','payment_issue') order by monitoring_requested_at nulls last,created_at,id",[workspaceId])).rows;
    for(const [i,row]of systems.entries()){
      const next=monitoringState(sub,i,row.monitoring);
      if(next!==row.monitoring){await c.query('update systems set monitoring=$2 where id=$1',[row.id,next]);await c.query("insert into system_events(workspace_id,system_id,kind,detail) values($1,$2,'monitoring_changed',$3)",[workspaceId,row.id,JSON.stringify({from:row.monitoring,to:next,subscription_status:sub?.status??'none'})]);}
    }
  });
}
