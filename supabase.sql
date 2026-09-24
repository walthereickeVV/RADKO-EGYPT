-- Run in Supabase Dashboard → SQL Editor. Then create the owner account in
-- Authentication → Users and add its UUID to admin_users (see README.md).

create table if not exists public.admin_users (
  id uuid primary key references auth.users(id) on delete cascade
);

create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  name_ar text not null check (char_length(name_ar) between 1 and 150),
  name_en text not null check (char_length(name_en) between 1 and 150),
  name_ru text not null check (char_length(name_ru) between 1 and 150),
  description_ar text not null default '' check (char_length(description_ar) <= 500),
  description_en text not null default '' check (char_length(description_en) <= 500),
  description_ru text not null default '' check (char_length(description_ru) <= 500),
  category text not null default 'other' check (category in ('medical','skincare','wellness','other')),
  price numeric(10,2) check (price >= 0),
  image_url text check (image_url is null or (char_length(image_url) <= 1000 and image_url like 'https://%')),
  available boolean not null default true,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.site_settings (
  id integer primary key check (id = 1),
  owner_name_ar text not null default '' check (char_length(owner_name_ar) <= 150),
  owner_name_en text not null default '' check (char_length(owner_name_en) <= 150),
  owner_name_ru text not null default '' check (char_length(owner_name_ru) <= 150),
  owner_photo_url text check (owner_photo_url is null or (char_length(owner_photo_url) <= 1000 and owner_photo_url like 'https://%'))
);

alter table public.admin_users enable row level security;
alter table public.products enable row level security;
alter table public.site_settings enable row level security;

create or replace function public.is_radko_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.admin_users where id = (select auth.uid())); $$;

revoke all on function public.is_radko_admin() from public;
grant execute on function public.is_radko_admin() to anon, authenticated;
grant usage on schema public to anon, authenticated;
grant select on public.admin_users to authenticated;
grant select on public.products, public.site_settings to anon, authenticated;
grant insert, update, delete on public.products, public.site_settings to authenticated;

drop policy if exists "Owner checks own membership" on public.admin_users;
create policy "Owner checks own membership" on public.admin_users
  for select to authenticated using (id = (select auth.uid()));

drop policy if exists "Public catalog or owner" on public.products;
create policy "Public catalog or owner" on public.products
  for select to anon, authenticated using (active or public.is_radko_admin());
drop policy if exists "Owner inserts products" on public.products;
create policy "Owner inserts products" on public.products
  for insert to authenticated with check (public.is_radko_admin());
drop policy if exists "Owner updates products" on public.products;
create policy "Owner updates products" on public.products
  for update to authenticated using (public.is_radko_admin()) with check (public.is_radko_admin());
drop policy if exists "Owner deletes products" on public.products;
create policy "Owner deletes products" on public.products
  for delete to authenticated using (public.is_radko_admin());

drop policy if exists "Public owner profile" on public.site_settings;
create policy "Public owner profile" on public.site_settings
  for select to anon, authenticated using (true);
drop policy if exists "Owner inserts profile" on public.site_settings;
create policy "Owner inserts profile" on public.site_settings
  for insert to authenticated with check (public.is_radko_admin());
drop policy if exists "Owner updates profile" on public.site_settings;
create policy "Owner updates profile" on public.site_settings
  for update to authenticated using (public.is_radko_admin()) with check (public.is_radko_admin());

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('images','images',true,3145728,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=excluded.public,
  file_size_limit=excluded.file_size_limit, allowed_mime_types=excluded.allowed_mime_types;

drop policy if exists "Owner uploads images" on storage.objects;
create policy "Owner uploads images" on storage.objects
  for insert to authenticated with check (
    bucket_id = 'images' and public.is_radko_admin()
    and (name like 'products/%' or name like 'owner/%')
  );
drop policy if exists "Owner deletes images" on storage.objects;
create policy "Owner deletes images" on storage.objects
  for delete to authenticated using (bucket_id = 'images' and public.is_radko_admin());

-- Next, after creating the Auth user, run separately with their real UUID:
-- insert into public.admin_users (id) values ('xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx');
