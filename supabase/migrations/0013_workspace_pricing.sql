-- Existing subscriptions retain their terms until explicitly migrated.
alter table public.subscriptions add column if not exists billing_model text not null default 'per_system' check (billing_model in ('per_system','workspace'));
