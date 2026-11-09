-- Shared reports can contain validated external package identifiers as well as
-- Canary catalog ids. External OSV records are retained in package_checks and
-- immutable report snapshots, not copied into the curated public catalog.
-- Keep ownership FKs, unique finding identity, source attribution and RLS intact.
-- Only trusted server code may write findings; anon/authenticated remain read-only.
alter table app_findings drop constraint app_findings_advisory_id_fkey;
comment on column app_findings.advisory_id is
  'Canary catalog id or external OSV finding id. Resolve external evidence from the authorized shared report/cache; never imply editorial review.';
