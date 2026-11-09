-- Website contact requests (e.g. volume buyers). Written only by the server route,
-- read only by operators through the app. The app sends no outbound email about them.
create table contact_requests (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  topic text not null check (topic in ('volume', 'general')),
  name text not null check (length(name) between 1 and 120),
  email text not null check (length(email) between 3 and 254),
  organization text check (length(organization) <= 160),
  systems_estimate int check (systems_estimate between 1 and 100000),
  message text check (length(message) <= 4000),
  status text not null default 'new' check (status in ('new', 'handled')),
  handled_at timestamptz
);
create index contact_requests_created on contact_requests (created_at desc);

alter table contact_requests enable row level security;
-- No policies: no client access at all.
revoke all on contact_requests from anon, authenticated;
