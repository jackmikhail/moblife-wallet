-- Moblife Wallet: RP cash tracker for the Habboon mafia roleplay.
-- Tables are locked down (RLS on, no policies, no grants). Every read/write goes
-- through SECURITY DEFINER RPCs that check the wallet's secret key.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.rp_wallets (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 2 and 24),
  name_key text generated always as (lower(btrim(name))) stored,
  balance bigint not null default 0 check (balance >= 0),
  made boolean not null default false,
  key_hash text not null,
  created_at timestamptz not null default now(),
  last_seen timestamptz not null default now()
);
create unique index if not exists rp_wallets_name_key_idx on public.rp_wallets(name_key);

create table if not exists public.rp_tx (
  id bigint generated always as identity primary key,
  kind text not null check (kind in ('open','transfer','cash_in','cash_out')),
  from_id uuid references public.rp_wallets(id),
  to_id uuid references public.rp_wallets(id),
  from_name text,
  to_name text,
  amount bigint not null check (amount > 0),
  note text,
  created_at timestamptz not null default now()
);
create index if not exists rp_tx_from_idx on public.rp_tx(from_id, id desc);
create index if not exists rp_tx_to_idx on public.rp_tx(to_id, id desc);

alter table public.rp_wallets enable row level security;
alter table public.rp_tx enable row level security;
revoke all on public.rp_wallets from anon, authenticated;
revoke all on public.rp_tx from anon, authenticated;

-- ---------- helpers ----------
create or replace function public.rp__hash(p_key text) returns text
language sql immutable as $$
  select encode(extensions.digest(p_key, 'sha256'), 'hex')
$$;
revoke execute on function public.rp__hash(text) from public, anon, authenticated;

create or replace function public.rp__auth(p_id uuid, p_key text) returns public.rp_wallets
language plpgsql security definer set search_path = public, extensions as $$
declare w public.rp_wallets;
begin
  if p_id is null or p_key is null then raise exception 'bad_key'; end if;
  select * into w from public.rp_wallets where id = p_id;
  if not found or w.key_hash <> public.rp__hash(p_key) then raise exception 'bad_key'; end if;
  return w;
end $$;
revoke execute on function public.rp__auth(uuid, text) from public, anon, authenticated;

create or replace function public.rp__notify(p_wallet uuid, p_payload jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  perform realtime.send(p_payload, 'tx', 'rpw:' || p_wallet::text, false);
exception when others then
  -- realtime is a nicety; never fail the money movement because of it
  null;
end $$;
revoke execute on function public.rp__notify(uuid, jsonb) from public, anon, authenticated;

create or replace function public.rp__tx_json(t public.rp_tx) returns jsonb
language sql immutable as $$
  select jsonb_build_object(
    'id', t.id, 'kind', t.kind, 'amount', t.amount, 'note', t.note,
    'from_id', t.from_id, 'to_id', t.to_id, 'from_name', t.from_name, 'to_name', t.to_name,
    'at', t.created_at)
$$;
revoke execute on function public.rp__tx_json(public.rp_tx) from public, anon, authenticated;

-- ---------- public RPCs ----------

-- Open a wallet. Civilians start with at most $5,000; made guys choose any figure.
create or replace function public.rp_create_wallet(p_name text, p_start bigint, p_made boolean default false)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  v_name text := btrim(coalesce(p_name, ''));
  v_key text := encode(gen_random_bytes(16), 'hex');
  v_start bigint := coalesce(p_start, 0);
  v_made boolean := coalesce(p_made, false);
  w public.rp_wallets;
  t public.rp_tx;
begin
  if v_name !~ '^[A-Za-z0-9][A-Za-z0-9 .''_-]{1,23}$' then raise exception 'bad_name'; end if;
  if v_start < 0 then raise exception 'bad_amount'; end if;
  if not v_made and v_start > 5000 then raise exception 'over_civilian_cap'; end if;
  if v_start > 1000000000 then raise exception 'bad_amount'; end if;

  begin
    insert into public.rp_wallets(name, balance, made, key_hash)
      values (v_name, v_start, v_made, public.rp__hash(v_key))
      returning * into w;
  exception when unique_violation then
    raise exception 'name_taken';
  end;

  if v_start > 0 then
    insert into public.rp_tx(kind, to_id, to_name, amount, note)
      values ('open', w.id, w.name, v_start, 'Opened wallet') returning * into t;
  end if;

  return jsonb_build_object('id', w.id, 'key', v_key, 'name', w.name, 'balance', w.balance,
                            'made', w.made, 'created_at', w.created_at);
end $$;

-- Get a wallet back on a new device: character name + the recovery key shown at setup.
create or replace function public.rp_recover(p_name text, p_key text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare w public.rp_wallets;
begin
  select * into w from public.rp_wallets
    where name_key = lower(btrim(coalesce(p_name, ''))) and key_hash = public.rp__hash(coalesce(p_key, ''));
  if not found then raise exception 'bad_key'; end if;
  return jsonb_build_object('id', w.id, 'name', w.name, 'balance', w.balance, 'made', w.made, 'created_at', w.created_at);
end $$;

-- Wallet + last 40 ledger lines. Only the key holder can see a balance.
create or replace function public.rp_me(p_id uuid, p_key text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  w public.rp_wallets;
  v_ledger jsonb;
begin
  w := public.rp__auth(p_id, p_key);
  if w.last_seen < now() - interval '2 minutes' then
    update public.rp_wallets set last_seen = now() where id = w.id;
  end if;
  select coalesce(jsonb_agg(public.rp__tx_json(t) order by t.id desc), '[]'::jsonb) into v_ledger
    from (select * from public.rp_tx where from_id = w.id or to_id = w.id order by id desc limit 40) t;
  return jsonb_build_object(
    'wallet', jsonb_build_object('id', w.id, 'name', w.name, 'balance', w.balance, 'made', w.made, 'created_at', w.created_at),
    'ledger', v_ledger);
end $$;

-- Recipient picker: names only, never balances.
create or replace function public.rp_lookup(p_q text)
returns table(id uuid, name text, made boolean, last_seen timestamptz)
language sql security definer stable set search_path = public, extensions as $$
  select id, name, made, last_seen from public.rp_wallets
   where char_length(btrim(coalesce(p_q, ''))) >= 1
     and name_key like lower(btrim(p_q)) || '%'
   order by last_seen desc limit 8
$$;

-- Hand cash to another character. Atomic: both balances move in one transaction.
create or replace function public.rp_send(p_id uuid, p_key text, p_to text, p_amount bigint, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me public.rp_wallets;
  r public.rp_wallets;
  t public.rp_tx;
  v_note text := nullif(left(btrim(coalesce(p_note, '')), 80), '');
begin
  me := public.rp__auth(p_id, p_key);
  if p_amount is null or p_amount <= 0 or p_amount > 1000000000 then raise exception 'bad_amount'; end if;

  select * into r from public.rp_wallets where name_key = lower(btrim(coalesce(p_to, '')));
  if not found then raise exception 'no_such_wallet'; end if;
  if r.id = me.id then raise exception 'self_send'; end if;

  -- lock both rows in a fixed order so two crossing sends can't deadlock
  perform 1 from public.rp_wallets where id in (me.id, r.id) order by id for update;
  select * into me from public.rp_wallets where id = me.id;
  if me.balance < p_amount then raise exception 'insufficient_funds'; end if;

  update public.rp_wallets set balance = balance - p_amount, last_seen = now() where id = me.id;
  update public.rp_wallets set balance = balance + p_amount where id = r.id;

  insert into public.rp_tx(kind, from_id, to_id, from_name, to_name, amount, note)
    values ('transfer', me.id, r.id, me.name, r.name, p_amount, v_note) returning * into t;

  perform public.rp__notify(me.id, public.rp__tx_json(t));
  perform public.rp__notify(r.id, public.rp__tx_json(t));

  return jsonb_build_object('balance', me.balance - p_amount, 'tx', public.rp__tx_json(t));
end $$;

-- Cash that didn't come from another player (a job, a score, the house). Always logged.
create or replace function public.rp_adjust(p_id uuid, p_key text, p_amount bigint, p_note text default null)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  me public.rp_wallets;
  t public.rp_tx;
  v_note text := nullif(left(btrim(coalesce(p_note, '')), 80), '');
  v_new bigint;
begin
  me := public.rp__auth(p_id, p_key);
  if p_amount is null or p_amount = 0 or abs(p_amount) > 1000000000 then raise exception 'bad_amount'; end if;

  perform 1 from public.rp_wallets where id = me.id for update;
  select balance into v_new from public.rp_wallets where id = me.id;
  v_new := v_new + p_amount;
  if v_new < 0 then raise exception 'insufficient_funds'; end if;

  update public.rp_wallets set balance = v_new, last_seen = now() where id = me.id;

  if p_amount > 0 then
    insert into public.rp_tx(kind, to_id, to_name, amount, note)
      values ('cash_in', me.id, me.name, p_amount, v_note) returning * into t;
  else
    insert into public.rp_tx(kind, from_id, from_name, amount, note)
      values ('cash_out', me.id, me.name, -p_amount, v_note) returning * into t;
  end if;

  perform public.rp__notify(me.id, public.rp__tx_json(t));
  return jsonb_build_object('balance', v_new, 'tx', public.rp__tx_json(t));
end $$;

grant execute on function public.rp_create_wallet(text, bigint, boolean) to anon, authenticated;
grant execute on function public.rp_recover(text, text) to anon, authenticated;
grant execute on function public.rp_me(uuid, text) to anon, authenticated;
grant execute on function public.rp_lookup(text) to anon, authenticated;
grant execute on function public.rp_send(uuid, text, text, bigint, text) to anon, authenticated;
grant execute on function public.rp_adjust(uuid, text, bigint, text) to anon, authenticated;

notify pgrst, 'reload schema';
