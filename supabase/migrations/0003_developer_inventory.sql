-- Free developer inventory monitoring (canary-evidence/1), per the companion's
-- docs/API-CONTRACT.md persistence model. Private to the owning workspace; never joined
-- to billable systems or subscription quantities. Composite keys keep every row inside
-- one project and one workspace.

create table developer_projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references workspaces(id) on delete cascade,
  name text not null check (length(name) between 1 and 120),
  monitoring_mode text not null default 'developer_inventory_free' check (monitoring_mode = 'developer_inventory_free'),
  -- pending: evidence may be stored, owner has not enrolled; active: enrolled (free);
  -- paused: owner paused notices and re-evaluation
  state text not null default 'pending' check (state in ('pending', 'active', 'paused')),
  latest_evidence_id uuid,
  created_at timestamptz not null default now(),
  enrolled_at timestamptz,
  deleted_at timestamptz,
  unique (id, workspace_id)
);

create table developer_project_tokens (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null,
  workspace_id uuid not null,
  token_hash text not null unique,
  token_hint text not null, -- last 4 characters, for recognition only
  scopes text[] not null check (scopes <@ array['evidence:read', 'evidence:write'] and cardinality(scopes) > 0),
  label text,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  foreign key (project_id, workspace_id) references developer_projects (id, workspace_id) on delete cascade
);

create table developer_evidence (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null,
  workspace_id uuid not null,
  schema_version text not null check (schema_version = 'canary-evidence/1'),
  bundle_sha256 text not null check (bundle_sha256 ~ '^[a-f0-9]{64}$'),
  idempotency_key text not null check (idempotency_key ~ '^[a-f0-9]{64}$'),
  canonical_body text not null,
  receipt jsonb not null,
  submitted_via text not null check (submitted_via in ('api', 'web_bundle', 'web_files')),
  submitted_by text not null, -- 'token:<id>' or 'user:<id>'
  repository_id text not null,
  repository_commit text,
  repository_dirty boolean,
  deployment jsonb, -- developer_supplied_unverified; never treated as verified production state
  inventory_format text not null,
  unknowns jsonb not null,
  audit_summary jsonb not null, -- upstream verdict counts and context, preserved as supplied
  has_detailed_findings boolean not null,
  bundle_created_at timestamptz not null,
  received_at timestamptz not null default now(),
  unique (workspace_id, project_id, idempotency_key),
  unique (id, project_id, workspace_id),
  foreign key (project_id, workspace_id) references developer_projects (id, workspace_id) on delete cascade
);
create index developer_evidence_project on developer_evidence (project_id, received_at desc);

alter table developer_projects
  add constraint developer_projects_latest_fk foreign key (latest_evidence_id, id, workspace_id)
  references developer_evidence (id, project_id, workspace_id) deferrable initially deferred;

create table developer_components (
  evidence_id uuid not null,
  project_id uuid not null,
  workspace_id uuid not null,
  instance int not null,
  ecosystem text not null check (ecosystem = 'npm'),
  name text not null,
  exact_version text,
  purl text,
  relationship text not null,
  development boolean,
  optional boolean,
  source_id text not null,
  primary key (evidence_id, instance),
  foreign key (evidence_id, project_id, workspace_id) references developer_evidence (id, project_id, workspace_id) on delete cascade
);
create index developer_components_name on developer_components (ecosystem, name);

create table developer_evaluations (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null,
  workspace_id uuid not null,
  evidence_id uuid not null,
  catalog_revision bigint not null,
  matcher_revision text not null,
  state text not null check (state in ('pending', 'running', 'completed', 'failed')),
  results jsonb,
  coverage jsonb,
  error text,
  attempts int not null default 0,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  unique (project_id, evidence_id, catalog_revision, matcher_revision),
  foreign key (evidence_id, project_id, workspace_id) references developer_evidence (id, project_id, workspace_id) on delete cascade
);
create index developer_evaluations_project on developer_evaluations (project_id, created_at desc);

create table developer_events (
  id bigserial primary key,
  workspace_id uuid not null,
  project_id uuid not null,
  evidence_id uuid not null,
  advisory_id text not null,
  advisory_revision int not null,
  kind text not null check (kind in ('newly_relevant', 'status_changed', 'no_longer_relevant', 'advisory_withdrawn')),
  prior_status text,
  current_status text,
  detail jsonb not null default '{}',
  created_at timestamptz not null default now(),
  seen_at timestamptz,
  unique (evidence_id, advisory_id, advisory_revision, kind),
  foreign key (evidence_id, project_id, workspace_id) references developer_evidence (id, project_id, workspace_id) on delete cascade
);
create index developer_events_ws on developer_events (workspace_id, created_at desc);

-- ───────────── Model usage and operation accounting (operator-only) ─────────────
-- Never stores prompts, private reports or secrets: only counts, ids and timings.
create table model_usage (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  provider text not null,
  model text not null,
  operation text not null, -- e.g. nightly_feed_extraction
  cost_pool text not null check (cost_pool in ('shared_feed', 'per_customer')),
  run_id text, -- e.g. feed intake id
  request_id text,
  attempt int not null,
  outcome text not null check (outcome in ('success', 'failure')),
  error_class text,
  latency_ms int not null,
  input_tokens int,
  output_tokens int,
  cache_read_tokens int,
  cache_write_tokens int,
  estimated_cost_usd numeric(12, 6), -- null = unknown (missing usage or rate)
  rate_table text, -- dated rate table used for the estimate
  measurement text not null check (measurement in ('live', 'backfilled_from_record', 'fixture'))
);
create index model_usage_created on model_usage (created_at desc);

create table operation_log (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  operation text not null, -- initial_analysis, cached_lookup, reanalysis, developer_upload, developer_evaluation, ...
  cost_pool text not null check (cost_pool in ('shared_feed', 'per_customer')),
  model_calls int not null default 0,
  latency_ms int,
  outcome text not null,
  measurement text not null default 'live' check (measurement in ('live', 'fixture'))
);
create index operation_log_created on operation_log (created_at desc);

-- ───────────── RLS ─────────────
alter table developer_projects enable row level security;
alter table developer_project_tokens enable row level security;
alter table developer_evidence enable row level security;
alter table developer_components enable row level security;
alter table developer_evaluations enable row level security;
alter table developer_events enable row level security;
alter table model_usage enable row level security;
alter table operation_log enable row level security;

create policy developer_projects_owner on developer_projects for select using (workspace_id in (select public.my_workspace_ids()));
create policy developer_evidence_owner on developer_evidence for select using (workspace_id in (select public.my_workspace_ids()));
create policy developer_components_owner on developer_components for select using (workspace_id in (select public.my_workspace_ids()));
create policy developer_evaluations_owner on developer_evaluations for select using (workspace_id in (select public.my_workspace_ids()));
create policy developer_events_owner on developer_events for select using (workspace_id in (select public.my_workspace_ids()));
-- Token rows (even hashes) and accounting tables have no client policies: service-only.

revoke insert, update, delete on developer_projects, developer_project_tokens, developer_evidence, developer_components,
  developer_evaluations, developer_events, model_usage, operation_log from anon, authenticated;
revoke select on developer_project_tokens, model_usage, operation_log from anon, authenticated;
