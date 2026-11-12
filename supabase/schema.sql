-- Solaria database schema: run in an ACTIVE Supabase project's SQL editor.
-- Do not use a service_role key in the public site.
create schema if not exists private;
create table if not exists public.profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 role text not null default 'citizen' check (role in ('citizen','minister','king')),
 created_at timestamptz not null default now()
);
create or replace function private.is_staff() returns boolean language sql security definer set search_path = '' stable as $$
 select exists(select 1 from public.profiles where user_id = (select auth.uid()) and role in ('king','minister'));
$$;
create or replace function private.is_king() returns boolean language sql security definer set search_path = '' stable as $$
 select exists(select 1 from public.profiles where user_id = (select auth.uid()) and role = 'king');
$$;
revoke all on function private.is_staff() from public;
revoke all on function private.is_king() from public;
grant usage on schema private to authenticated;
grant execute on function private.is_staff() to authenticated;
grant execute on function private.is_king() to authenticated;
create or replace function private.new_citizen_profile() returns trigger language plpgsql security definer set search_path = '' as $$
begin
 insert into public.profiles(user_id,role) values (new.id,'citizen') on conflict (user_id) do nothing;
 return new;
end $$;
drop trigger if exists on_auth_user_created_solaria on auth.users;
create trigger on_auth_user_created_solaria after insert on auth.users for each row execute function private.new_citizen_profile();
insert into public.profiles(user_id) select id from auth.users on conflict(user_id) do nothing;

create table if not exists public.applications (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null unique references auth.users(id) on delete cascade,
 display_name text not null check (char_length(display_name) between 2 and 60),
 region text not null check(region in ('العاصمة الذهبية','الشمال الملكي','الساحل الشمسي','الوادي الذهبي')),
 status text not null default 'pending' check(status in ('pending','approved','rejected')),
 created_at timestamptz not null default now()
);
create table if not exists public.decrees (
 id uuid primary key default gen_random_uuid(),
 author_id uuid not null references auth.users(id),
 title text not null check (char_length(title) between 3 and 120),
 body text not null check (char_length(body) between 3 and 4000),
 created_at timestamptz not null default now()
);
create table if not exists public.tickets (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 category text not null check(category in ('اقتراح','طلب خدمة','شكوى')),
 body text not null check(char_length(body) between 3 and 1000),
 status text not null default 'open' check(status in ('open','closed')),
 created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
alter table public.applications enable row level security;
alter table public.decrees enable row level security;
alter table public.tickets enable row level security;

create policy "profile own or staff read" on public.profiles for select to authenticated using (user_id=(select auth.uid()) or (select private.is_staff()));
create policy "application own or staff read" on public.applications for select to authenticated using (user_id=(select auth.uid()) or (select private.is_staff()));
create policy "application self request" on public.applications for insert to authenticated with check(user_id=(select auth.uid()) and status='pending');
create policy "application edit own pending" on public.applications for update to authenticated using (user_id=(select auth.uid()) and status='pending') with check (user_id=(select auth.uid()) and status='pending');
create policy "application staff decision" on public.applications for update to authenticated using ((select private.is_staff())) with check ((select private.is_staff()));
create policy "public decrees read" on public.decrees for select to anon,authenticated using(true);
create policy "king writes decrees" on public.decrees for insert to authenticated with check(author_id=(select auth.uid()) and (select private.is_king()));
create policy "ticket own or staff read" on public.tickets for select to authenticated using(user_id=(select auth.uid()) or (select private.is_staff()));
create policy "ticket self submission" on public.tickets for insert to authenticated with check(user_id=(select auth.uid()) and status='open');
create policy "ticket staff resolution" on public.tickets for update to authenticated using ((select private.is_staff())) with check ((select private.is_staff()));

-- Approved-citizen count visible without exposing names, emails or application records.
create table if not exists public.kingdom_stats (singleton boolean primary key default true check(singleton),citizens integer not null default 0);
insert into public.kingdom_stats(singleton,citizens) select true,count(*)::integer from public.applications where status='approved' on conflict(singleton) do update set citizens=excluded.citizens;
create or replace function private.refresh_stats() returns trigger language plpgsql security definer set search_path='' as $$
begin
 update public.kingdom_stats set citizens=(select count(*)::integer from public.applications where status='approved') where singleton=true;
 return null;
end $$;
drop trigger if exists solaria_refresh_stats on public.applications;
create trigger solaria_refresh_stats after insert or update of status or delete on public.applications for each statement execute function private.refresh_stats();
alter table public.kingdom_stats enable row level security;
create policy "read anonymous counts" on public.kingdom_stats for select to anon,authenticated using(true);
revoke all on public.kingdom_stats from anon,authenticated;
grant select on public.kingdom_stats to anon,authenticated;
grant select on public.profiles,public.applications,public.decrees,public.tickets to authenticated;
grant insert,update on public.applications to authenticated;
grant insert on public.decrees to authenticated;
grant insert,update on public.tickets to authenticated;
grant select on public.decrees to anon;

-- Only after your own account has signed up, promote it manually by exact email:
-- update public.profiles set role='king'
-- where user_id=(select id from auth.users where email='YOUR_EMAIL@example.com');
-- Do NOT add a public API for self-promotion.
