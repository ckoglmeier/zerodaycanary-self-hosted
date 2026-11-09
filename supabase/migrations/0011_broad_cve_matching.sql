-- Versioned broad inventory; legacy immutable bundles keep their original rules.
alter table developer_evidence drop constraint developer_evidence_schema_version_check;
alter table developer_evidence add constraint developer_evidence_schema_version_check
 check (schema_version in ('canary-evidence/1','canary-evidence/2','canary-cve-report/1','canary-cve-report/2'));
alter table developer_components drop constraint developer_components_ecosystem_check;
alter table developer_components add constraint developer_components_ecosystem_check check(length(ecosystem) between 1 and 100);
-- Unknown provenance is never permission to disclose a private package name.
alter table developer_components add column public_registry boolean not null default false;
create table package_checks (
 ecosystem text not null, name text not null, version text not null,
 checked_at timestamptz not null, records jsonb not null,
 primary key(ecosystem,name,version)
);
create table package_check_history (
 id bigserial primary key,ecosystem text not null,name text not null,version text not null,
 checked_at timestamptz not null,records jsonb not null
);
create index package_check_history_lookup on package_check_history(ecosystem,name,version,checked_at desc);
alter table package_checks enable row level security;
alter table package_check_history enable row level security;
revoke all on package_checks,package_check_history from anon,authenticated;
