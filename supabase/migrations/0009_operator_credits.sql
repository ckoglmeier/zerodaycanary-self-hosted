-- Operator credits are Stripe invoice-balance adjustments, never monitoring grants.
-- Reserve a durable intent before the external request so uncertain outcomes can
-- be retried with the same Stripe key. Identity/amount/reason are immutable.
create table billing_credits (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id),
  actor_id uuid not null references auth.users(id),
  actor_email text not null,
  client_key uuid not null unique,
  amount_cents integer not null check (amount_cents between 100 and 100000),
  currency text not null default 'usd' check (currency = 'usd'),
  reason text not null check (length(reason) between 3 and 500),
  stripe_customer_id text not null,
  stripe_transaction_id text unique,
  livemode boolean not null,
  state text not null default 'pending' check (state in ('pending','applied')),
  last_error text,
  created_at timestamptz not null default now(),
  applied_at timestamptz,
  check ((state = 'applied') = (stripe_transaction_id is not null and applied_at is not null))
);
create index billing_credits_workspace on billing_credits(workspace_id,created_at desc);
create unique index billing_credits_one_pending on billing_credits(workspace_id) where state='pending';
alter table billing_credits enable row level security;
revoke all on billing_credits from anon,authenticated;

create function protect_billing_credit() returns trigger language plpgsql as $$
begin
  if tg_op = 'DELETE' then raise exception 'Credit audit records cannot be deleted'; end if;
  if (to_jsonb(new) - array['state','last_error','stripe_transaction_id','applied_at'])
     is distinct from (to_jsonb(old) - array['state','last_error','stripe_transaction_id','applied_at'])
     or old.state = 'applied' then
    raise exception 'Credit audit records are immutable';
  end if;
  return new;
end $$;
create trigger billing_credit_immutable before update or delete on billing_credits
for each row execute function protect_billing_credit();
