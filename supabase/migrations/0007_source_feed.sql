-- Source-supplied catalog is distinct from operator-reviewed, matchable alerts.
create table source_imports (
  id uuid primary key default gen_random_uuid(),
  sha256 text not null unique,
  filename text not null,
  created_by text not null,
  created_at timestamptz not null default now(),
  row_count int not null,
  changed_count int not null default 0
);
create table source_feed_revisions (
  id bigint generated always as identity primary key,
  import_id uuid not null references source_imports(id),
  created_at timestamptz not null default now()
);
create table source_vulnerabilities (
  id text primary key,
  content_hash text not null,
  revision bigint not null references source_feed_revisions(id),
  record jsonb not null,
  updated_at timestamptz not null,
  priority_candidate boolean not null,
  search text not null
);
create table source_vulnerability_aliases (
  alias text primary key,
  source_id text not null references source_vulnerabilities(id)
);
create table source_vulnerability_versions (
  source_id text not null references source_vulnerabilities(id),
  revision bigint not null references source_feed_revisions(id),
  record jsonb not null,
  primary key(source_id, revision)
);
create index source_versions_snapshot on source_vulnerability_versions(source_id, revision desc);
create index source_versions_revision on source_vulnerability_versions(revision);
create index source_priority on source_vulnerabilities(priority_candidate);
alter table advisory_drafts add column source_id text references source_vulnerabilities(id);
alter table advisory_drafts add column source_hash text;
create unique index source_review_once on advisory_drafts(source_id, source_hash) where source_id is not null;

-- Editorial selection must never gate the matching engine or the reviewed API.
alter table advisories add column featured boolean not null default false;
update advisories set featured = true where status = 'published' and
  (severity = 'critical' or exploitation = 'known_exploited' or
   (exploitation = 'public_poc' and severity = 'high'));
create table alert_feature_history (
  id bigint generated always as identity primary key,
  advisory_id text not null references advisories(id),
  featured boolean not null,
  reason text not null,
  created_by text not null,
  created_at timestamptz not null default now()
);
alter table source_imports enable row level security;
alter table source_feed_revisions enable row level security;
alter table source_vulnerabilities enable row level security;
alter table source_vulnerability_aliases enable row level security;
alter table source_vulnerability_versions enable row level security;
alter table alert_feature_history enable row level security;
revoke all on source_imports,source_feed_revisions,source_vulnerabilities,
  source_vulnerability_aliases,source_vulnerability_versions,alert_feature_history from anon,authenticated;
