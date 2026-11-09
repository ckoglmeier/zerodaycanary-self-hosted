-- App-scoped private conversations, attributed owner answers and explicit report shares.
-- All writes authorize server-side. Read policies are a second boundary, not a public API.
alter table systems add constraint systems_workspace_pair unique (id, workspace_id);
alter table workspaces add column nonprofit boolean not null default false;
alter table workspaces add column nonprofit_attested_at timestamptz;
alter table workspaces add column nonprofit_attested_by uuid references auth.users(id);

create table app_findings (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  system_id uuid not null,
  advisory_id text not null references advisories(id),
  component_key text not null,
  product text not null,
  assessment_status text not null,
  workflow_status text not null default 'check_required' check (workflow_status in ('check_required','owner_not_affected','owner_affected','unknown','fix_reported','no_match_in_report','withdrawn')),
  evidence jsonb not null,
  signature text not null,
  source_kind text not null check (source_kind in ('public','shared_report')),
  source_at timestamptz not null,
  source_id text not null,
  first_seen_at timestamptz not null default now(),
  last_checked_at timestamptz not null default now(),
  changed_at timestamptz not null default now(),
  unique (system_id, advisory_id, component_key),
  unique (id, system_id, workspace_id),
  foreign key (system_id,workspace_id) references systems(id,workspace_id)
);
create table app_conversations (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  system_id uuid not null unique,
  created_at timestamptz not null default now(),
  unique (id,workspace_id),
  foreign key (system_id,workspace_id) references systems(id,workspace_id)
);
create table conversation_invites (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references app_conversations(id),
  email text not null check (email = lower(email) and length(email) between 3 and 254),
  expires_at timestamptz not null,
  accepted_by uuid references auth.users(id),
  accepted_at timestamptz,
  revoked_at timestamptz,
  delivery_state text not null default 'pending' check (delivery_state in ('pending','sent','failed','unconfigured')),
  delivery_error text,
  created_at timestamptz not null default now()
);
create table app_requests (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  system_id uuid not null,
  conversation_id uuid not null,
  finding_id uuid,
  recipient_email text not null,
  question text not null check (length(question) between 1 and 4000),
  client_key uuid not null,
  created_by uuid not null references auth.users(id),
  state text not null default 'waiting' check (state in ('waiting','answered','needs_evidence')),
  created_at timestamptz not null default now(),
  unique (conversation_id,client_key),
  unique (id,workspace_id),
  foreign key (conversation_id,workspace_id) references app_conversations(id,workspace_id),
  foreign key (system_id,workspace_id) references systems(id,workspace_id),
  foreign key (finding_id,system_id,workspace_id) references app_findings(id,system_id,workspace_id)
);
create table owner_answers (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null references app_requests(id),
  outcome text not null check (outcome in ('not_affected','affected','unknown')),
  reason text not null check (length(reason) between 1 and 2000),
  remediation_plan text,
  target_date date,
  date_pending boolean not null default false,
  evidence_note text check (length(evidence_note) <= 4000),
  actor_id uuid not null references auth.users(id),
  actor_email text not null,
  client_key uuid not null,
  created_at timestamptz not null default now(),
  unique(request_id,client_key),
  check (outcome <> 'affected' or (length(trim(remediation_plan)) > 0 and (target_date is not null or date_pending)))
);
create table report_pages (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null unique references developer_projects(id),
  owner_workspace_id uuid not null references workspaces(id),
  created_at timestamptz not null default now()
);
create table shared_reports (
  id uuid primary key default gen_random_uuid(),
  page_id uuid not null references report_pages(id),
  evidence_id uuid not null references developer_evidence(id),
  evaluation_id uuid not null references developer_evaluations(id),
  snapshot jsonb not null,
  remediation_plan text,
  target_date date,
  date_pending boolean not null default false,
  shared_by uuid not null references auth.users(id),
  created_at timestamptz not null default now(),
  unique(page_id,evaluation_id)
);
create table report_grants (
  id uuid primary key default gen_random_uuid(),
  page_id uuid not null references report_pages(id),
  email text not null check (email = lower(email)),
  granted_by uuid not null references auth.users(id),
  revoked_at timestamptz,
  created_at timestamptz not null default now(),
  unique(page_id,email)
);
create table system_report_links (
  system_id uuid not null,
  workspace_id uuid not null,
  page_id uuid not null references report_pages(id),
  recipient_email text not null,
  created_at timestamptz not null default now(),
  primary key(system_id,page_id),
  foreign key(system_id,workspace_id) references systems(id,workspace_id)
);
create table conversation_messages (
  id uuid primary key default gen_random_uuid(),
  conversation_id uuid not null references app_conversations(id),
  request_id uuid references app_requests(id),
  author_id uuid not null references auth.users(id),
  author_email text not null,
  kind text not null check (kind in ('request','reply','answer','report','progress')),
  body text not null check (length(body) between 1 and 4000),
  answer_id uuid references owner_answers(id),
  report_id uuid references shared_reports(id),
  client_key uuid not null,
  created_at timestamptz not null default now(),
  unique(conversation_id,client_key)
);
create table finding_transitions (
  id bigint generated always as identity primary key,
  finding_id uuid not null references app_findings(id),
  from_status text,
  to_status text not null,
  detail jsonb not null default '{}',
  transition_key text not null,
  created_at timestamptz not null default now(),
  unique(finding_id,transition_key)
);
alter table app_findings enable row level security;
alter table app_conversations enable row level security;
alter table app_requests enable row level security;
alter table owner_answers enable row level security;
alter table conversation_invites enable row level security;
alter table conversation_messages enable row level security;
alter table report_pages enable row level security;
alter table shared_reports enable row level security;
alter table report_grants enable row level security;
alter table system_report_links enable row level security;
alter table finding_transitions enable row level security;
create policy findings_owner on app_findings for select using (workspace_id in (select public.my_workspace_ids()));
create policy conversations_owner on app_conversations for select using (workspace_id in (select public.my_workspace_ids()));
create policy requests_owner on app_requests for select using (workspace_id in (select public.my_workspace_ids()));
create policy report_pages_owner on report_pages for select using (owner_workspace_id in (select public.my_workspace_ids()));
create policy reports_owner on shared_reports for select using (page_id in (select id from report_pages));
-- Recipient access is checked against a server-validated Supabase user/email, never a JWT
-- email supplied by a browser. No direct PostgREST recipient policies are exposed.
revoke all on app_findings,app_conversations,app_requests,owner_answers,conversation_invites,conversation_messages,
  report_pages,shared_reports,report_grants,system_report_links,finding_transitions from anon,authenticated;
-- Findings can contain evidence derived from a report whose grant was revoked.
-- Their projection is server-only so current grants always govern new reads.
grant select on app_conversations,app_requests,report_pages,shared_reports to authenticated;
