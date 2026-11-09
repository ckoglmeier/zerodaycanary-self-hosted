-- Optional dated developer declarations, separate from legacy audit verdicts and
-- deterministic matching. Existing evidence and shared snapshots remain unchanged.
alter table developer_evidence add column cve_review jsonb;
alter table developer_evidence drop constraint developer_evidence_schema_version_check;
alter table developer_evidence add constraint developer_evidence_schema_version_check
  check (schema_version in ('canary-evidence/1','canary-cve-report/1'));
