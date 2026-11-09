-- Keep development acceptance runs in the audit trail without presenting them as
-- real feed reviews. This flag is service-only; operator HTTP input cannot set it.
alter table feed_intakes add column if not exists is_test boolean not null default false;
comment on column feed_intakes.is_test is 'Synthetic acceptance fixture; excluded from public feed review health.';

-- Known fixture identities from the shipped test scripts only. Do not classify
-- arbitrary operator briefs by their text or discard genuine failures.
update feed_intakes set is_test = true
where (created_by = 'failure-test' and attribution = 'SYNTHETIC' and brief like 'SYNTHETIC failure test %')
   or (created_by = 'sync-test' and attribution = 'SYNTHETIC sync test' and brief = 'SYNTHETIC')
   or (created_by = 'dev-test' and attribution = 'SYNTHETIC developer test' and brief = 'SYNTHETIC');

-- Explicit, non-publication cost measurements from launch QA (including the
-- failed SDK compatibility probe); these are not nightly feed attempts.
update feed_intakes set is_test = true
where attribution in (
  'COST SAMPLE (live measurement, not for publication)',
  'COST SAMPLE 2 (live measurement, not for publication)',
  'COST SAMPLE 2b (live measurement, not for publication)'
);
