import "server-only";
import { z } from "zod";
import { HttpError, type Viewer } from "./auth";
import { env } from "./env";
import { one, q, tx } from "./db";
import { ensureCustomer, stripe } from "./billing";

export function assertAdministrator(v: Viewer) {
  if (!v.isOperator || !v.emailVerified || !env.operatorEmails().includes(v.email.toLowerCase()))
    throw new HttpError(403, "Administrator access required.");
}

export const creditInput = z.object({
  amount: z.string().regex(/^\d{1,4}(\.\d{1,2})?$/, "Enter a dollar amount with at most two decimal places.")
    .transform(s => { const [d,c=""] = s.split("."); return Number(d)*100+Number(c.padEnd(2,"0")); })
    .pipe(z.number().int().min(100, "Minimum credit is $1.").max(100000, "Maximum credit is $1,000 per adjustment.")),
  reason: z.string().trim().min(3).max(500), client_key: z.uuid(),
});

type Credit = { id:string; workspace_id:string; actor_id:string; client_key:string; amount_cents:number; currency:string; reason:string;
  stripe_customer_id:string; stripe_transaction_id:string|null; livemode:boolean; state:'pending'|'applied'; created_at:Date; last_error:string|null };

export async function accounts(v:Viewer,search="",page=1) {
  assertAdministrator(v);
  const term=search.trim().slice(0,200),offset=(Math.max(1,Math.min(10000,Math.trunc(page)||1))-1)*50;
  return q<{id:string;email:string;created_at:Date;last_sign_in_at:Date|null;verified:boolean;workspace_id:string|null;name:string|null;status:string|null;systems:string;projects:string}>(
    `select u.id,u.email,u.created_at,u.last_sign_in_at,(u.email_confirmed_at is not null) verified,w.id workspace_id,w.name,sub.status,
     (select count(*) from systems s where s.workspace_id=w.id and s.removed_at is null) systems,
     (select count(*) from developer_projects p where p.workspace_id=w.id and p.deleted_at is null) projects
     from auth.users u left join workspaces w on w.owner_id=u.id left join subscriptions sub on sub.workspace_id=w.id
     where $1='' or strpos(lower(coalesce(u.email,'')||' '||coalesce(w.name,'')||' '||u.id::text),lower($1))>0
     order by u.created_at desc,u.id limit 51 offset $2`,[term,offset]);
}

export async function account(v:Viewer,id:string) {
  assertAdministrator(v);
  if(!z.uuid().safeParse(id).success)throw new HttpError(404,"Account not found.");
  const a=await one<{id:string;email:string;created_at:Date;last_sign_in_at:Date|null;verified:boolean;workspace_id:string|null;name:string|null;nonprofit:boolean;stripe_customer_id:string|null}>(
    `select u.id,u.email,u.created_at,u.last_sign_in_at,(u.email_confirmed_at is not null) verified,w.id workspace_id,w.name,w.nonprofit,w.stripe_customer_id
     from auth.users u left join workspaces w on w.owner_id=u.id where u.id=$1`,[id]);
  if(!a)throw new HttpError(404,"Account not found.");
  const [systems,projects,subscription,credits]=await Promise.all([
    q<{id:string;label:string;monitoring:string;created_at:Date}>("select id,label,monitoring,created_at from systems where workspace_id=$1 and removed_at is null order by created_at desc limit 100",[a.workspace_id]),
    q<{id:string;name:string;state:string}>("select id,name,state from developer_projects where workspace_id=$1 and deleted_at is null order by created_at desc limit 100",[a.workspace_id]),
    one<{status:string;quantity:number;cancel_at_period_end:boolean}>("select status,quantity,cancel_at_period_end from subscriptions where workspace_id=$1",[a.workspace_id]),
    q<Credit & {actor_email:string;applied_at:Date|null}>("select * from billing_credits where workspace_id=$1 order by created_at desc limit 100",[a.workspace_id]),
  ]);
  return {a,systems,projects,subscription,credits};
}

// Read the provider's current invoice balance, not the sum of historical grants.
export async function creditBalance(workspaceId:string) {
  const ws=await one<{stripe_customer_id:string|null}>("select stripe_customer_id from workspaces where id=$1",[workspaceId]);
  if(!ws?.stripe_customer_id)return {available:0,due:0,livemode:!process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_')};
  const customer=await stripe().customers.retrieve(ws.stripe_customer_id);
  if(customer.deleted)throw new Error("Billing customer unavailable");
  if(customer.currency&&customer.currency!=='usd')throw new Error("Only USD monitoring credits are supported");
  return {available:Math.max(0,-customer.balance),due:Math.max(0,customer.balance),livemode:customer.livemode};
}

export async function grantCredit(v:Viewer,accountId:string,input:unknown) {
  assertAdministrator(v);
  const parsed=creditInput.safeParse(input);
  if(!parsed.success)throw new HttpError(400,parsed.error.issues[0]?.message||"Enter a valid credit.");
  const data=parsed.data,{a}=await account(v,accountId);
  if(!a.workspace_id)throw new HttpError(400,"This account has not opened a workspace yet.");
  if(process.env.VERCEL_ENV==='preview'&&!process.env.STRIPE_SECRET_KEY?.startsWith('sk_test_'))throw new HttpError(400,"Preview credits require Stripe test mode.");
  const customerId=await ensureCustomer(a.workspace_id,a.email),customer=await stripe().customers.retrieve(customerId);
  if(customer.deleted||(customer.currency&&customer.currency!=='usd'))throw new HttpError(400,"This billing account cannot accept USD credits.");
  const credit=await tx(async c=>{
    await c.query("select id from workspaces where id=$1 for update",[a.workspace_id]);
    const pending=(await c.query<{client_key:string}>("select client_key from billing_credits where workspace_id=$1 and state='pending'",[a.workspace_id])).rows[0];
    if(pending&&pending.client_key!==data.client_key)throw new HttpError(409,"An earlier credit is pending. Refresh this account and retry that adjustment first.");
    await c.query(`insert into billing_credits(workspace_id,actor_id,actor_email,client_key,amount_cents,reason,stripe_customer_id,livemode)
      values($1,$2,$3,$4,$5,$6,$7,$8) on conflict(client_key) do nothing`,[a.workspace_id,v.id,v.email,data.client_key,data.amount,data.reason,customerId,customer.livemode]);
    const row=(await c.query<Credit>("select * from billing_credits where client_key=$1",[data.client_key])).rows[0];
    if(row.workspace_id!==a.workspace_id||row.actor_id!==v.id||row.amount_cents!==data.amount||row.reason!==data.reason||row.stripe_customer_id!==customerId||row.livemode!==customer.livemode)
      throw new HttpError(409,"This credit request was already used with different details. Refresh before starting another adjustment.");
    return row;
  });
  if(credit.state==='applied')return credit;
  try {
    // Stripe may prune idempotency keys after 24 hours. Never reissue an old
    // ambiguous intent: look for its transaction first, otherwise require review.
    let adjustment;
    if(Date.now()-new Date(credit.created_at).getTime()>23*60*60*1000){
      for await(const t of stripe().customers.listBalanceTransactions(customerId,{limit:100})) {
        if(t.metadata?.canary_credit_id===credit.id){adjustment=t;break;}
      }
      if(!adjustment)throw new HttpError(409,"Credit outcome needs reconciliation in Stripe before retrying. No new credit was issued.");
    } else adjustment=await stripe().customers.createBalanceTransaction(customerId,{
      amount:-credit.amount_cents,currency:'usd',description:'Zero Day Canary monitoring credit',metadata:{canary_credit_id:credit.id,workspace_id:a.workspace_id},
    },{idempotencyKey:`canary-credit-${credit.id}`});
    if(adjustment.amount!==-credit.amount_cents||adjustment.currency!=='usd')throw new Error('Unexpected balance transaction');
    await q("update billing_credits set state='applied',stripe_transaction_id=$2,applied_at=now(),last_error=null where id=$1 and state='pending'",[credit.id,adjustment.id]);
    return {...credit,state:'applied' as const,stripe_transaction_id:adjustment.id};
  } catch(e) {
    await q("update billing_credits set last_error=$2 where id=$1 and state='pending'",[credit.id,'Outcome unconfirmed. Retry the same request; do not create a replacement credit.']);
    if(e instanceof HttpError)throw e;
    throw new HttpError(502,"Credit outcome is unconfirmed. Retry this same request to reconcile safely.");
  }
}
