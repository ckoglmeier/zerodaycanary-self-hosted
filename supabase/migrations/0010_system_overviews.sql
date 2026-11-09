-- Private historical context. Never joins shared scan observations or automatic findings.
create table system_overviews (
  system_id uuid primary key,
  workspace_id uuid not null,
  source text not null check(length(source) between 1 and 180),
  kind text not null check(kind in ('notes','text','pdf','docx')),
  pages integer check(pages between 1 and 40),
  extracted_text text not null check(length(extracted_text) between 1 and 120000),
  added_by uuid not null references auth.users(id),
  updated_at timestamptz not null default now(),
  foreign key(system_id,workspace_id) references systems(id,workspace_id)
);
alter table system_overviews enable row level security;
revoke all on system_overviews from anon,authenticated;
grant select,insert,update,delete on system_overviews to authenticated;
create policy system_overviews_owner on system_overviews for all to authenticated
  using (workspace_id in (select public.my_workspace_ids()) and exists(select 1 from systems s where s.id=system_id and s.workspace_id=system_overviews.workspace_id and s.removed_at is null))
  with check (added_by=auth.uid() and workspace_id in (select public.my_workspace_ids()) and exists(select 1 from systems s where s.id=system_id and s.workspace_id=system_overviews.workspace_id and s.removed_at is null));
