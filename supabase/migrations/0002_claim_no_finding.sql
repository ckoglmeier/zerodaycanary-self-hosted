-- Host upgrade outcome when the system had no affected finding before the claim:
-- the fresh check is recorded honestly instead of as a verified fix.
alter table host_claims drop constraint host_claims_state_check;
alter table host_claims add constraint host_claims_state_check
  check (state in ('reported', 'checking', 'fix_verified', 'still_affected', 'unable_to_confirm', 'check_failed', 'no_finding'));
