-- ════════════════════════════════════════════════════════════════
-- Duna.app — Admin da plataforma (assinaturas, planos, pagamentos)
-- Rodar inteiro no SQL Editor do Supabase. Pode rodar mais de uma vez.
-- ════════════════════════════════════════════════════════════════

-- 1) Administradores da plataforma -------------------------------
create table if not exists public.plataforma_admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  papel      text not null default 'admin' check (papel in ('dono','admin')),
  created_at timestamptz not null default now()
);

-- 2) Planos ------------------------------------------------------
create table if not exists public.planos (
  id            uuid primary key default gen_random_uuid(),
  nome          text not null,
  descricao     text,
  preco         numeric(10,2) not null default 0,
  periodicidade text not null default 'mensal'
                check (periodicidade in ('mensal','trimestral','semestral','anual','vitalicio')),
  dias_teste    int not null default 0,
  ativo         boolean not null default true,
  created_at    timestamptz not null default now()
);

-- 3) Assinatura de cada usuário (uma por usuário) ----------------
create table if not exists public.assinaturas (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  plano_id    uuid references public.planos(id) on delete set null,
  status      text not null default 'ativa'
              check (status in ('teste','ativa','inativa','cancelada')),
  inicio      date default current_date,
  expira_em   date,
  observacoes text,
  updated_at  timestamptz not null default now()
);

-- 4) Pagamentos recebidos (base do faturamento por mês) ----------
create table if not exists public.pagamentos_assinatura (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid references auth.users(id) on delete cascade,
  plano_id       uuid references public.planos(id) on delete set null,
  valor          numeric(10,2) not null,
  data_pagamento date not null default current_date,
  metodo         text,
  observacoes    text,
  created_at     timestamptz not null default now()
);
create index if not exists pagamentos_assinatura_data_idx on public.pagamentos_assinatura(data_pagamento);

-- 5) Funções de permissão ----------------------------------------
create or replace function public.is_plataforma_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.plataforma_admins where user_id = auth.uid());
$$;

create or replace function public.is_plataforma_dono()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.plataforma_admins where user_id = auth.uid() and papel = 'dono');
$$;

-- 6) RLS ---------------------------------------------------------
alter table public.plataforma_admins     enable row level security;
alter table public.planos                enable row level security;
alter table public.assinaturas           enable row level security;
alter table public.pagamentos_assinatura enable row level security;

drop policy if exists admins_select on public.plataforma_admins;
create policy admins_select on public.plataforma_admins for select using (public.is_plataforma_admin());
drop policy if exists admins_write on public.plataforma_admins;
create policy admins_write on public.plataforma_admins for all
  using (public.is_plataforma_dono()) with check (public.is_plataforma_dono());

-- Planos: qualquer usuário logado pode ver (para uma futura tela "Assine"); só admin altera
drop policy if exists planos_select on public.planos;
create policy planos_select on public.planos for select using (auth.uid() is not null);
drop policy if exists planos_write on public.planos;
create policy planos_write on public.planos for all
  using (public.is_plataforma_admin()) with check (public.is_plataforma_admin());

-- Assinaturas e pagamentos: o usuário vê os próprios; admin vê e altera tudo
drop policy if exists assinaturas_select on public.assinaturas;
create policy assinaturas_select on public.assinaturas for select
  using (user_id = auth.uid() or public.is_plataforma_admin());
drop policy if exists assinaturas_write on public.assinaturas;
create policy assinaturas_write on public.assinaturas for all
  using (public.is_plataforma_admin()) with check (public.is_plataforma_admin());

drop policy if exists pagamentos_select on public.pagamentos_assinatura;
create policy pagamentos_select on public.pagamentos_assinatura for select
  using (user_id = auth.uid() or public.is_plataforma_admin());
drop policy if exists pagamentos_write on public.pagamentos_assinatura;
create policy pagamentos_write on public.pagamentos_assinatura for all
  using (public.is_plataforma_admin()) with check (public.is_plataforma_admin());

-- 7) RPC: lista de usuários com perfil + assinatura (só admin) ----
drop function if exists public.admin_listar_usuarios();
create function public.admin_listar_usuarios()
returns table (
  user_id uuid, email text, criado_em timestamptz, ultimo_acesso timestamptz,
  email_confirmado boolean, nome text, sobrenome text, telefone text,
  plano_id uuid, status text, inicio date, expira_em date, observacoes text,
  papel_admin text, qtd_lancamentos bigint
)
language plpgsql stable security definer set search_path = public, auth as $$
begin
  if not public.is_plataforma_admin() then
    raise exception 'Acesso restrito a administradores';
  end if;
  return query
  select u.id, u.email::text, u.created_at, u.last_sign_in_at,
         (u.email_confirmed_at is not null),
         p.nome::text, p.sobrenome::text, p.telefone::text,
         a.plano_id, a.status, a.inicio, a.expira_em, a.observacoes,
         pa.papel,
         (select count(*) from public.transacoes t where t.user_id = u.id)
  from auth.users u
  left join public.perfis p             on p.user_id = u.id
  left join public.assinaturas a        on a.user_id = u.id
  left join public.plataforma_admins pa on pa.user_id = u.id
  order by u.created_at desc;
end $$;

-- 8) RPC: salvar perfil + assinatura de um usuário (só admin) -----
create or replace function public.admin_salvar_usuario(
  p_user_id uuid, p_nome text, p_sobrenome text, p_telefone text,
  p_plano_id uuid, p_status text, p_inicio date, p_expira_em date, p_observacoes text
) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_plataforma_admin() then
    raise exception 'Acesso restrito a administradores';
  end if;
  insert into public.perfis (user_id, nome, sobrenome, telefone)
  values (p_user_id, p_nome, p_sobrenome, p_telefone)
  on conflict (user_id) do update
    set nome = excluded.nome, sobrenome = excluded.sobrenome, telefone = excluded.telefone;
  insert into public.assinaturas (user_id, plano_id, status, inicio, expira_em, observacoes, updated_at)
  values (p_user_id, p_plano_id, coalesce(p_status,'ativa'), p_inicio, p_expira_em, p_observacoes, now())
  on conflict (user_id) do update
    set plano_id = excluded.plano_id, status = excluded.status, inicio = excluded.inicio,
        expira_em = excluded.expira_em, observacoes = excluded.observacoes, updated_at = now();
end $$;

-- 9) RPC: dar/tirar acesso de admin por e-mail (só o dono) --------
create or replace function public.admin_definir_admin(p_email text, p_admin boolean)
returns text
language plpgsql security definer set search_path = public, auth as $$
declare v_id uuid;
begin
  if not public.is_plataforma_dono() then
    raise exception 'Só o dono da plataforma pode alterar administradores';
  end if;
  select id into v_id from auth.users where lower(email) = lower(trim(p_email));
  if v_id is null then
    raise exception 'Nenhum usuário com o e-mail %', p_email;
  end if;
  if p_admin then
    insert into public.plataforma_admins (user_id, papel) values (v_id, 'admin')
    on conflict (user_id) do nothing;
  else
    delete from public.plataforma_admins where user_id = v_id and papel <> 'dono';
  end if;
  return v_id::text;
end $$;

grant execute on function public.is_plataforma_admin()  to authenticated;
grant execute on function public.is_plataforma_dono()   to authenticated;
grant execute on function public.admin_listar_usuarios() to authenticated;
grant execute on function public.admin_salvar_usuario(uuid,text,text,text,uuid,text,date,date,text) to authenticated;
grant execute on function public.admin_definir_admin(text,boolean) to authenticated;

-- 10) Você como DONO — confira se o e-mail está certo -------------
insert into public.plataforma_admins (user_id, papel)
select id, 'dono' from auth.users where lower(email) = 'eufelipedlima@gmail.com'
on conflict (user_id) do update set papel = 'dono';

-- Conferência: deve retornar 1 linha com papel = 'dono'
select u.email, pa.papel from public.plataforma_admins pa join auth.users u on u.id = pa.user_id;
