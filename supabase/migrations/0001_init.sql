-- Zero Day Canary launch schema.
-- Public intelligence (advisories, catalog) is readable by anyone once published.
-- Shared public observations are readable only through a workspace's own systems.
-- Private buyer data is isolated per workspace by RLS. Server routes that use the
-- service role perform their own authorization checks.

create extension if not exists pgcrypto;

-- ───────────────────────── Public intelligence ─────────────────────────

create table catalog_revisions (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  intake_id uuid,
  note text not null
);

-- Feed reviews: every operator review outcome, including "no changes" and failures,
-- so freshness is never claimed without an actual successful review.
create table feed_reviews (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  intake_id uuid,
  outcome text not null check (outcome in ('published', 'no_changes', 'failed')),
  catalog_revision bigint references catalog_revisions(id),
  detail text
);

create table advisories (
  id text primary key, -- stable internal id (zdc-xxxxxxxx)
  status text not null check (status in ('published', 'withdrawn', 'superseded')),
  revision int not null,
  catalog_revision bigint not null references catalog_revisions(id),
  record jsonb not null, -- full normalized AdvisoryRecord for this revision
  exploitation text not null,
  severity text not null,
  product text not null,
  identifiers text[] not null,
  search text not null, -- lowercase product/title/ids for filtering
  reviewed_at timestamptz not null,
  updated_at timestamptz not null
);
create index advisories_catalog_rev on advisories (catalog_revision, id);
create index advisories_exploitation on advisories (exploitation);

-- Immutable revision history; corrections never overwrite earlier revisions.
create table advisory_revisions (
  advisory_id text not null references advisories(id),
  revision int not null,
  catalog_revision bigint not null references catalog_revisions(id),
  record jsonb not null,
  change_note text not null,
  created_at timestamptz not null default now(),
  created_by text not null,
  primary key (advisory_id, revision)
);

create table advisory_aliases (
  alias text primary key, -- normalized CVE/GHSA/vendor id
  advisory_id text not null references advisories(id),
  added_at timestamptz not null default now()
);

-- ───────────────────────── Operator intake (service-only) ─────────────────────────

create table feed_intakes (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  created_by text not null,
  brief text not null,
  brief_sha256 text not null,
  attribution text,
  status text not null check (status in ('extracting', 'extracted', 'failed', 'reviewed')),
  error text,
  model text,
  usage jsonb
);
create index feed_intakes_sha on feed_intakes (brief_sha256);

create table advisory_drafts (
  id uuid primary key default gen_random_uuid(),
  intake_id uuid not null references feed_intakes(id),
  created_at timestamptz not null default now(),
  draft jsonb not null, -- AdvisoryDraft, edited by the operator
  status text not null default 'draft' check (status in ('draft', 'published', 'rejected')),
  target_advisory_id text references advisories(id), -- set when the draft updates an existing record
  review_note text,
  reviewed_at timestamptz,
  published_advisory_id text references advisories(id)
);

-- ───────────────────────── Shared public observations ─────────────────────────

-- A scan scope is the canonical public URL that was examined. Shared across workspaces:
-- it holds only public evidence, never buyer identity or private evidence.
create table scan_scopes (
  id uuid primary key default gen_random_uuid(),
  scope_key text not null unique,
  url text not null,
  host text not null,
  created_at timestamptz not null default now()
);

create table observations (
  id uuid primary key default gen_random_uuid(),
  scope_id uuid not null references scan_scopes(id),
  observed_at timestamptz not null default now(),
  outcome text not null check (outcome in ('complete', 'partial', 'failed')),
  final_url text,
  evidence jsonb not null, -- { techs: TechObservation[], facts: {} }
  gaps jsonb not null default '[]',
  fetch_log jsonb not null default '[]',
  trigger text not null check (trigger in ('initial', 'reanalysis', 'host_upgrade', 'scheduled'))
);
create index observations_scope on observations (scope_id, observed_at desc);

create table scan_jobs (
  id uuid primary key default gen_random_uuid(),
  scope_id uuid not null references scan_scopes(id),
  status text not null check (status in ('queued', 'running', 'done', 'failed')),
  trigger text not null,
  attempts int not null default 0,
  lease_until timestamptz,
  observation_id uuid references observations(id),
  error text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
-- At most one active job per scope: concurrent requests reuse it.
create unique index scan_jobs_one_active on scan_jobs (scope_id) where status in ('queued', 'running');

-- ───────────────────────── Private workspace data ─────────────────────────

create table workspaces (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique references auth.users(id) on delete cascade,
  name text not null default 'My workspace',
  stripe_customer_id text unique,
  created_at timestamptz not null default now()
);

create table systems (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  scope_id uuid not null references scan_scopes(id),
  label text not null,
  business_use text,
  owner_vendor text,
  -- none: analyzed only; pending_payment: monitoring requested, awaiting verified payment;
  -- active: paid monitoring; paused: owner paused; payment_issue: subscription not in good standing
  monitoring text not null default 'none' check (monitoring in ('none', 'pending_payment', 'active', 'paused', 'payment_issue')),
  monitoring_requested_at timestamptz,
  host_request_token text not null unique default encode(gen_random_bytes(18), 'hex'),
  created_at timestamptz not null default now(),
  removed_at timestamptz
);
create unique index systems_one_per_scope on systems (workspace_id, scope_id) where removed_at is null;

-- Administrator-supplied version evidence: private to the workspace, never enters the shared cache.
create table system_evidence (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  system_id uuid not null references systems(id) on delete cascade,
  product text not null,
  version text not null,
  note text,
  created_at timestamptz not null default now()
);

-- Assessment snapshots: deterministic match of (observation + private evidence) against a catalog revision.
create table assessments (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  system_id uuid not null references systems(id) on delete cascade,
  observation_id uuid references observations(id),
  catalog_revision bigint,
  computed_at timestamptz not null default now(),
  results jsonb not null, -- AdvisoryAssessment[]
  summary jsonb not null -- { strongest, counts, coverage, gaps }
);
create index assessments_system on assessments (system_id, computed_at desc);

create table system_events (
  id bigserial primary key,
  workspace_id uuid not null references workspaces(id) on delete cascade,
  system_id uuid references systems(id) on delete cascade,
  kind text not null,
  detail jsonb not null default '{}',
  created_at timestamptz not null default now(),
  seen boolean not null default false
);
create index system_events_ws on system_events (workspace_id, created_at desc);

-- ───────────────────────── Host control and upgrade claims ─────────────────────────

create table host_challenges (
  id uuid primary key default gen_random_uuid(),
  scope_id uuid not null references scan_scopes(id),
  host text not null,
  token text not null unique,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  verified_at timestamptz,
  consumed_at timestamptz,
  verify_attempts int not null default 0
);

create table host_claims (
  id uuid primary key default gen_random_uuid(),
  scope_id uuid not null references scan_scopes(id),
  challenge_id uuid not null references host_challenges(id),
  product text not null,
  claimed_version text not null,
  upgraded_at timestamptz,
  reference_url text,
  created_at timestamptz not null default now(),
  -- reported → checking → fix_verified | still_affected | unable_to_confirm | check_failed
  state text not null default 'reported' check (state in ('reported', 'checking', 'fix_verified', 'still_affected', 'unable_to_confirm', 'check_failed')),
  before_observation_id uuid references observations(id),
  after_observation_id uuid references observations(id),
  outcome_detail text,
  updated_at timestamptz not null default now()
);
create index host_claims_scope on host_claims (scope_id, created_at desc);

-- ───────────────────────── Billing (written only by verified webhooks) ─────────────────────────

create table subscriptions (
  workspace_id uuid primary key references workspaces(id) on delete cascade,
  stripe_subscription_id text unique,
  status text not null,
  quantity int not null default 0,
  current_period_end timestamptz,
  cancel_at_period_end boolean not null default false,
  stripe_event_created bigint not null default 0, -- newest event applied; older events are ignored
  updated_at timestamptz not null default now()
);

create table stripe_events (
  id text primary key,
  type text not null,
  created bigint not null,
  received_at timestamptz not null default now(),
  processed_at timestamptz,
  error text
);

create table rate_limits (
  key text not null,
  window_start timestamptz not null,
  count int not null default 0,
  primary key (key, window_start)
);

-- ───────────────────────── Workspace bootstrap ─────────────────────────

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.workspaces (owner_id) values (new.id) on conflict do nothing;
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ───────────────────────── Row-level security ─────────────────────────

alter table catalog_revisions enable row level security;
alter table feed_reviews enable row level security;
alter table advisories enable row level security;
alter table advisory_revisions enable row level security;
alter table advisory_aliases enable row level security;
alter table feed_intakes enable row level security;
alter table advisory_drafts enable row level security;
alter table scan_scopes enable row level security;
alter table observations enable row level security;
alter table scan_jobs enable row level security;
alter table workspaces enable row level security;
alter table systems enable row level security;
alter table system_evidence enable row level security;
alter table assessments enable row level security;
alter table system_events enable row level security;
alter table host_challenges enable row level security;
alter table host_claims enable row level security;
alter table subscriptions enable row level security;
alter table stripe_events enable row level security;
alter table rate_limits enable row level security;

-- Public catalog: anyone may read published/withdrawn/superseded records.
create policy catalog_public_read on catalog_revisions for select using (true);
create policy feed_reviews_public_read on feed_reviews for select using (true);
create policy advisories_public_read on advisories for select using (true);
create policy advisory_revisions_public_read on advisory_revisions for select using (true);
create policy advisory_aliases_public_read on advisory_aliases for select using (true);

-- Helper: workspaces owned by the caller.
create function public.my_workspace_ids() returns setof uuid
language sql stable security definer set search_path = public as $$
  select id from workspaces where owner_id = auth.uid()
$$;

create policy workspaces_owner on workspaces for select using (owner_id = auth.uid());
create policy workspaces_owner_update on workspaces for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());

create policy systems_owner_select on systems for select using (workspace_id in (select public.my_workspace_ids()));
create policy systems_owner_update on systems for update using (workspace_id in (select public.my_workspace_ids()))
  with check (workspace_id in (select public.my_workspace_ids()));

create policy system_evidence_owner on system_evidence for select using (workspace_id in (select public.my_workspace_ids()));
create policy assessments_owner on assessments for select using (workspace_id in (select public.my_workspace_ids()));
create policy system_events_owner on system_events for select using (workspace_id in (select public.my_workspace_ids()));
create policy subscriptions_owner on subscriptions for select using (workspace_id in (select public.my_workspace_ids()));

-- Shared scopes, observations and host claims are visible only through the caller's own systems.
create policy scan_scopes_via_system on scan_scopes for select using (
  exists (select 1 from systems s where s.scope_id = scan_scopes.id and s.workspace_id in (select public.my_workspace_ids()))
);
create policy observations_via_system on observations for select using (
  exists (select 1 from systems s where s.scope_id = observations.scope_id and s.workspace_id in (select public.my_workspace_ids()))
);
create policy host_claims_via_system on host_claims for select using (
  exists (select 1 from systems s where s.scope_id = host_claims.scope_id and s.workspace_id in (select public.my_workspace_ids()))
);

-- Column-level write limits: clients may only rename/describe their systems.
-- Monitoring state, scope and billing fields change only through server routes.
revoke insert, update, delete on all tables in schema public from anon, authenticated;
grant update (label, business_use, owner_vendor) on systems to authenticated;
grant update (name) on workspaces to authenticated;
revoke execute on function public.handle_new_user() from anon, authenticated, public;
