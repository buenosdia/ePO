# Enterprise PowerShell Orchestrator (EPO) v2

A hardened, multi-tenant orchestration platform for running PowerShell workloads across Windows infrastructure with auditable change control, credential isolation, and zero-trust defaults. This plan captures the reference architecture, database schema, service code, and operational guidance needed to stand up the stack.

---

## 1) Architecture Overview

**Components**
- **PostgreSQL 17**: Authoritative store with row-level security (RLS), immutable auditing, and tenant scoping. All business logic exposed through `SECURITY DEFINER` functions rather than ad-hoc table writes.
- **PostgREST**: Thin REST facade bound to database roles (`app_anon`, `app_user`, `app_admin`, `app_agent`). JWT claims drive both the DB role and application roles used inside the database.
- **Auth Gateway (Node.js + Express)**: Handles Local + LDAP(S) authentication, Argon2id hashing, token refresh, and agent bootstrap flows. Issues JWTs (HS512) embedding `role`, `app_roles[]`, `tenant_id`, and optional `agent_id` claims.
- **EPO Agent (PowerShell 7 service)**: Pulls work via signed JWT, verifies script integrity/signatures, decrypts credentials with its private key, executes runs (local or WinRM/PowerShell remoting), and streams structured logs.
- **React Frontend (Vite + TS)**: Admin console for managing scripts, credentials, jobs, schedules, and run history. Talks only to PostgREST/Auth Gateway using short-lived tokens stored in memory.

**Security Model**
- **Tenant isolation**: Every row carries a `tenant_id`; RLS enforces tenant scoping for users and agents.
- **Application RBAC**: JWTs include `app_roles` (admin/operator/auditor). Helper functions (`epo.user_has_role`) gate DML paths.
- **Credential handling**: Secrets stored as RSA-OAEP ciphertext under an agent public key or as external vault references. No plaintext secrets or reversible hashes in the DB.
- **Code integrity**: Script versions are immutable, hashed (SHA-256), optionally signed, and policy can require signed content.
- **Auditing**: Every mutating statement hits `audit.audit_log`; audit rows record tenant, PK, before/after, caller, and timestamp.
- **Operational boundaries**: Only stored procedures mutate runtime tables (`job_runs`, `job_run_targets`, logs). Agents never write directly outside vetted RPCs.

**Job Lifecycle**
1. Operator uploads script & version, optionally attaching Authenticode signature metadata.
2. Operator creates a job (targets + credentials + schedule) and activates it.
3. Run queued manually, via schedule evaluator, or API. Stored proc materializes `job_runs` + `job_run_targets` in a single transaction.
4. Agent claims queued work using `FOR UPDATE SKIP LOCKED`, updates run state to `running`, and downloads script/credentials.
5. Agent executes targets in isolated runspaces, streaming logs through definer RPCs.
6. Agent marks each target/run succeeded or failed; auditors consume immutable history.

---

## 2) PostgreSQL 17 Schema (with RLS, auditing, tenancy)

> Save as `db/epo_schema.sql`. Requires extensions `uuid-ossp`, `pgcrypto`, `pg_trgm`, `citext`.

```sql
-- ============================================================================
-- Enterprise PowerShell Orchestrator (EPO) v2 - PostgreSQL 17 schema
-- Requires extensions: uuid-ossp, pgcrypto, pg_trgm, citext
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS citext;

CREATE SCHEMA IF NOT EXISTS epo AUTHORIZATION CURRENT_USER;
CREATE SCHEMA IF NOT EXISTS audit AUTHORIZATION CURRENT_USER;

COMMENT ON SCHEMA epo IS 'Primary application schema for Enterprise PowerShell Orchestrator';
COMMENT ON SCHEMA audit IS 'Immutable audit trail schema';

-- Application roles are provisioned outside this script:
--   app_anon   (minimum read)
--   app_user   (operators)
--   app_admin  (tenant administrators)
--   app_agent  (execution agents)

CREATE TYPE epo.auth_provider AS ENUM ('local','ldap');
CREATE TYPE epo.app_role AS ENUM ('admin','operator','auditor');
CREATE TYPE epo.cred_algo AS ENUM ('rsa-oaep-sha256','external-ref');
CREATE TYPE epo.job_status AS ENUM ('draft','active','disabled');
CREATE TYPE epo.run_status AS ENUM ('queued','running','succeeded','failed','cancelled','abandoned');
CREATE TYPE epo.run_trigger AS ENUM ('schedule','manual','api');
CREATE TYPE epo.log_stream AS ENUM ('stdout','stderr','progress','diagnostic');
CREATE TYPE epo.script_visibility AS ENUM ('private','tenant');

CREATE OR REPLACE FUNCTION epo.request_claims()
RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb,
    '{}'::jsonb
  );
$$;
COMMENT ON FUNCTION epo.request_claims IS 'Parses PostgREST-injected JWT claims into jsonb ({} when absent).';

CREATE OR REPLACE FUNCTION epo.current_user_id()
RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN epo.request_claims() ? 'sub' THEN (epo.request_claims() ->> 'sub')::uuid
    WHEN epo.request_claims() ? 'user_id' THEN (epo.request_claims() ->> 'user_id')::uuid
    ELSE NULL
  END;
$$;
COMMENT ON FUNCTION epo.current_user_id IS 'Returns UUID of authenticated user (sub/user_id claim).';

CREATE OR REPLACE FUNCTION epo.current_agent_id()
RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN epo.request_claims() ? 'agent_id' THEN (epo.request_claims() ->> 'agent_id')::uuid
    ELSE NULL
  END;
$$;
COMMENT ON FUNCTION epo.current_agent_id IS 'Returns UUID of authenticated agent (agent_id claim).';

CREATE OR REPLACE FUNCTION epo.current_tenant_id()
RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN epo.request_claims() ? 'tenant_id' THEN (epo.request_claims() ->> 'tenant_id')::uuid
    ELSE NULL
  END;
$$;
COMMENT ON FUNCTION epo.current_tenant_id IS 'Returns tenant UUID from JWT (tenant_id claim).';

CREATE OR REPLACE FUNCTION epo.current_app_roles()
RETURNS text[] LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN epo.request_claims() ? 'app_roles' THEN
      COALESCE(
        (SELECT array_agg(value) FROM jsonb_array_elements_text(epo.request_claims()->'app_roles') AS t(value)),
        ARRAY[]::text[]
      )
    WHEN epo.request_claims() ? 'app_role' THEN ARRAY[epo.request_claims()->>'app_role']
    ELSE ARRAY[]::text[]
  END;
$$;
COMMENT ON FUNCTION epo.current_app_roles IS 'Returns application roles (admin/operator/auditor) from JWT.';

CREATE OR REPLACE FUNCTION epo.user_has_role(p_role text)
RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT p_role = ANY(epo.current_app_roles());
$$;
COMMENT ON FUNCTION epo.user_has_role IS 'True when current JWT includes the requested app role.';

CREATE OR REPLACE FUNCTION epo.require_tenant_id()
RETURNS uuid LANGUAGE plpgsql STABLE AS $$
DECLARE
  v uuid;
BEGIN
  v := epo.current_tenant_id();
  IF v IS NULL THEN
    RAISE EXCEPTION 'tenant context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v;
END;
$$;
COMMENT ON FUNCTION epo.require_tenant_id IS 'Returns tenant_id or raises when claim missing.';

CREATE OR REPLACE FUNCTION epo.require_user_id()
RETURNS uuid LANGUAGE plpgsql STABLE AS $$
DECLARE
  v uuid;
BEGIN
  v := epo.current_user_id();
  IF v IS NULL THEN
    RAISE EXCEPTION 'user context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v;
END;
$$;
COMMENT ON FUNCTION epo.require_user_id IS 'Returns user_id or raises when claim missing.';

CREATE OR REPLACE FUNCTION epo.require_agent_id()
RETURNS uuid LANGUAGE plpgsql STABLE AS $$
DECLARE
  v uuid;
BEGIN
  v := epo.current_agent_id();
  IF v IS NULL THEN
    RAISE EXCEPTION 'agent context missing' USING ERRCODE = '42501';
  END IF;
  RETURN v;
END;
$$;
COMMENT ON FUNCTION epo.require_agent_id IS 'Returns agent_id or raises when claim missing.';

CREATE TABLE audit.audit_log (
  id          bigserial PRIMARY KEY,
  tenant_id   uuid,
  table_name  text NOT NULL,
  action      text NOT NULL CHECK (action IN ('INSERT','UPDATE','DELETE')),
  row_pk      jsonb NOT NULL,
  old_row     jsonb,
  new_row     jsonb,
  by_user     uuid,
  at          timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE audit.audit_log IS 'Immutable record of every DML change performed through the platform.';

CREATE OR REPLACE FUNCTION audit.fn_write()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  v_row jsonb := to_jsonb(COALESCE(NEW, OLD));
  v_pk  jsonb;
  v_tenant uuid;
BEGIN
  IF TG_ARGV[0] IS NOT NULL THEN
    v_pk := jsonb_build_object(TG_ARGV[0], v_row -> TG_ARGV[0]);
  ELSE
    v_pk := jsonb_build_object('id', v_row -> 'id');
  END IF;

  IF v_row ? 'tenant_id' AND NULLIF(v_row ->> 'tenant_id', '') IS NOT NULL THEN
    v_tenant := (v_row ->> 'tenant_id')::uuid;
  ELSE
    v_tenant := epo.current_tenant_id();
  END IF;

  INSERT INTO audit.audit_log
    (table_name, action, row_pk, old_row, new_row, by_user, tenant_id)
  VALUES
    (TG_TABLE_SCHEMA||'.'||TG_TABLE_NAME, TG_OP, v_pk,
     CASE WHEN TG_OP IN ('UPDATE','DELETE') THEN to_jsonb(OLD) END,
     CASE WHEN TG_OP IN ('INSERT','UPDATE') THEN to_jsonb(NEW) END,
     epo.current_user_id(), v_tenant);
  RETURN COALESCE(NEW, OLD);
END;
$$;
COMMENT ON FUNCTION audit.fn_write IS 'Row-change audit trigger. TG_ARGV[0] = PK column name (optional).';

CREATE OR REPLACE FUNCTION epo.tg_touch_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;
COMMENT ON FUNCTION epo.tg_touch_updated_at IS 'Maintains updated_at timestamp columns.';

CREATE TABLE epo.tenants (
  id        uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name      text NOT NULL UNIQUE,
  slug      citext NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE epo.tenants IS 'Logical boundary for multi-tenant isolation.';

CREATE TABLE epo.users (
  id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id     uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  username      citext NOT NULL,
  email         citext,
  full_name     text,
  auth_provider epo.auth_provider NOT NULL DEFAULT 'local',
  password_hash text,
  is_active     boolean NOT NULL DEFAULT true,
  mfa_enforced  boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, username),
  UNIQUE (tenant_id, email)
);
COMMENT ON TABLE epo.users IS 'End users (local or LDAP) scoped to a tenant.';
CREATE TRIGGER trg_users_touch BEFORE UPDATE ON epo.users
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_users_audit AFTER INSERT OR UPDATE OR DELETE ON epo.users
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.user_roles (
  user_id    uuid REFERENCES epo.users(id) ON DELETE CASCADE,
  role       epo.app_role NOT NULL,
  granted_by uuid REFERENCES epo.users(id),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role)
);
COMMENT ON TABLE epo.user_roles IS 'Application roles (admin/operator/auditor) per user.';
CREATE TRIGGER trg_user_roles_audit AFTER INSERT OR UPDATE OR DELETE ON epo.user_roles
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('user_id');

CREATE TABLE epo.agents (
  id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id      uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  name           text NOT NULL,
  public_key_pem text NOT NULL,
  version        text,
  last_seen      timestamptz,
  created_by     uuid REFERENCES epo.users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
COMMENT ON TABLE epo.agents IS 'Registered execution agents keyed by tenant.';
CREATE TRIGGER trg_agents_touch BEFORE UPDATE ON epo.agents
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_agents_audit AFTER INSERT OR UPDATE OR DELETE ON epo.agents
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.scripts (
  id           uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id    uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  name         text NOT NULL,
  description  text,
  visibility   epo.script_visibility NOT NULL DEFAULT 'private',
  created_by   uuid NOT NULL REFERENCES epo.users(id),
  updated_by   uuid REFERENCES epo.users(id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
COMMENT ON TABLE epo.scripts IS 'Logical script definition; versions stored separately.';
CREATE TRIGGER trg_scripts_touch BEFORE UPDATE ON epo.scripts
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_scripts_audit AFTER INSERT OR UPDATE OR DELETE ON epo.scripts
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.script_versions (
  id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  script_id      uuid NOT NULL REFERENCES epo.scripts(id) ON DELETE CASCADE,
  version        integer NOT NULL,
  content        text NOT NULL,
  content_sha256 bytea NOT NULL,
  is_signed      boolean NOT NULL DEFAULT false,
  signature      bytea,
  signed_by      text,
  released_by    uuid REFERENCES epo.users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (script_id, version)
);
COMMENT ON TABLE epo.script_versions IS 'Immutable script code per version (with hash/signature metadata).';
CREATE INDEX idx_script_versions_script ON epo.script_versions(script_id);
CREATE TRIGGER trg_script_versions_audit AFTER INSERT OR UPDATE OR DELETE ON epo.script_versions
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.credentials (
  id                 uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id          uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  name               text NOT NULL,
  username           text NOT NULL,
  cipher_text        bytea,
  algorithm          epo.cred_algo NOT NULL DEFAULT 'rsa-oaep-sha256',
  external_reference text,
  pubkey_fingerprint text,
  created_by         uuid NOT NULL REFERENCES epo.users(id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (
    (algorithm = 'rsa-oaep-sha256' AND cipher_text IS NOT NULL AND pubkey_fingerprint IS NOT NULL)
    OR (algorithm = 'external-ref' AND external_reference IS NOT NULL)
  ),
  UNIQUE (tenant_id, name)
);
COMMENT ON TABLE epo.credentials IS 'Stored execution credentials (ciphertext or external reference).';
CREATE TRIGGER trg_credentials_touch BEFORE UPDATE ON epo.credentials
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_credentials_audit AFTER INSERT OR UPDATE OR DELETE ON epo.credentials
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.servers (
  id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id      uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  hostname       text NOT NULL,
  description    text,
  transport      text NOT NULL DEFAULT 'wsman' CHECK (transport IN ('wsman','ssh','local')),
  run_as_credential uuid REFERENCES epo.credentials(id) ON DELETE SET NULL,
  created_by     uuid REFERENCES epo.users(id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, hostname)
);
COMMENT ON TABLE epo.servers IS 'Managed servers / endpoints by tenant.';
CREATE TRIGGER trg_servers_touch BEFORE UPDATE ON epo.servers
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_servers_audit AFTER INSERT OR UPDATE OR DELETE ON epo.servers
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.schedules (
  id               uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id        uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  name             text NOT NULL,
  cron_expression  text NOT NULL,
  timezone         text NOT NULL,
  next_run_at      timestamptz,
  last_evaluated_at timestamptz,
  created_by       uuid REFERENCES epo.users(id),
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
COMMENT ON TABLE epo.schedules IS 'Cron-like schedule definitions per tenant.';
CREATE TRIGGER trg_schedules_touch BEFORE UPDATE ON epo.schedules
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_schedules_audit AFTER INSERT OR UPDATE OR DELETE ON epo.schedules
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.jobs (
  id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  tenant_id         uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  name              text NOT NULL,
  description       text,
  script_id         uuid NOT NULL REFERENCES epo.scripts(id) ON DELETE RESTRICT,
  script_version_id uuid REFERENCES epo.script_versions(id),
  schedule_id       uuid REFERENCES epo.schedules(id) ON DELETE SET NULL,
  status            epo.job_status NOT NULL DEFAULT 'draft',
  run_as_credential uuid REFERENCES epo.credentials(id) ON DELETE SET NULL,
  created_by        uuid NOT NULL REFERENCES epo.users(id),
  updated_by        uuid REFERENCES epo.users(id),
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
COMMENT ON TABLE epo.jobs IS 'Job definition binding script version, targets, schedule, and credentials.';
CREATE TRIGGER trg_jobs_touch BEFORE UPDATE ON epo.jobs
FOR EACH ROW EXECUTE FUNCTION epo.tg_touch_updated_at();
CREATE TRIGGER trg_jobs_audit AFTER INSERT OR UPDATE OR DELETE ON epo.jobs
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.job_targets (
  id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_id         uuid NOT NULL REFERENCES epo.jobs(id) ON DELETE CASCADE,
  server_id      uuid NOT NULL REFERENCES epo.servers(id) ON DELETE CASCADE,
  credential_id  uuid REFERENCES epo.credentials(id) ON DELETE SET NULL,
  parameters     jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_id, server_id)
);
COMMENT ON TABLE epo.job_targets IS 'Per-target configuration for job execution.';
CREATE TRIGGER trg_job_targets_audit AFTER INSERT OR UPDATE OR DELETE ON epo.job_targets
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.job_runs (
  id               uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_id           uuid NOT NULL REFERENCES epo.jobs(id) ON DELETE CASCADE,
  tenant_id        uuid NOT NULL REFERENCES epo.tenants(id) ON DELETE CASCADE,
  script_version_id uuid NOT NULL REFERENCES epo.script_versions(id),
  trigger          epo.run_trigger NOT NULL,
  requested_by     uuid REFERENCES epo.users(id),
  agent_id         uuid REFERENCES epo.agents(id),
  status           epo.run_status NOT NULL DEFAULT 'queued',
  queued_at        timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  completed_at     timestamptz,
  summary          text,
  cancellation_requested boolean NOT NULL DEFAULT false,
  retry_of         uuid REFERENCES epo.job_runs(id),
  UNIQUE (id)
);
COMMENT ON TABLE epo.job_runs IS 'Execution instances produced by scheduler or manual trigger.';
CREATE INDEX idx_job_runs_status ON epo.job_runs (tenant_id, status, queued_at);
CREATE INDEX idx_job_runs_job ON epo.job_runs (job_id, queued_at DESC);
CREATE TRIGGER trg_job_runs_audit AFTER INSERT OR UPDATE OR DELETE ON epo.job_runs
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.job_run_targets (
  id             uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_run_id     uuid NOT NULL REFERENCES epo.job_runs(id) ON DELETE CASCADE,
  server_id      uuid NOT NULL REFERENCES epo.servers(id),
  credential_id  uuid REFERENCES epo.credentials(id),
  status         epo.run_status NOT NULL DEFAULT 'queued',
  started_at     timestamptz,
  completed_at   timestamptz,
  exit_code      integer,
  output_digest  bytea,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (job_run_id, server_id)
);
COMMENT ON TABLE epo.job_run_targets IS 'Per-target tracking for a job run.';
CREATE INDEX idx_job_run_targets_run ON epo.job_run_targets (job_run_id);
CREATE TRIGGER trg_job_run_targets_audit AFTER INSERT OR UPDATE OR DELETE ON epo.job_run_targets
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('id');

CREATE TABLE epo.job_run_logs (
  id                bigserial PRIMARY KEY,
  job_run_target_id uuid NOT NULL REFERENCES epo.job_run_targets(id) ON DELETE CASCADE,
  ts                timestamptz NOT NULL DEFAULT now(),
  stream            epo.log_stream NOT NULL,
  seq               bigint NOT NULL DEFAULT 0,
  message           text NOT NULL
);
COMMENT ON TABLE epo.job_run_logs IS 'Structured log lines emitted while executing targets.';
CREATE INDEX idx_job_run_logs_target_ts ON epo.job_run_logs(job_run_target_id, ts);
CREATE TRIGGER trg_job_run_logs_audit AFTER INSERT OR UPDATE OR DELETE ON epo.job_run_logs
FOR EACH ROW EXECUTE FUNCTION audit.fn_write('job_run_target_id');
```

```sql
-- =============================
-- Stored procedures (security definer)
-- =============================

CREATE OR REPLACE FUNCTION epo.sp_register_agent(p_name text, p_public_key_pem text, p_version text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_tenant uuid := epo.require_tenant_id();
  v_user   uuid := epo.require_user_id();
  v_id     uuid;
BEGIN
  INSERT INTO epo.agents(tenant_id, name, public_key_pem, version, created_by)
  VALUES (v_tenant, p_name, p_public_key_pem, p_version, v_user)
  ON CONFLICT (tenant_id, name)
  DO UPDATE SET public_key_pem = EXCLUDED.public_key_pem,
                version        = COALESCE(EXCLUDED.version, epo.agents.version),
                updated_at     = now()
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;
COMMENT ON FUNCTION epo.sp_register_agent IS 'Upserts an agent keyed by name within the caller''s tenant.';

CREATE OR REPLACE FUNCTION epo.sp_enqueue_job(p_job_id uuid, p_trigger epo.run_trigger DEFAULT 'manual')
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_job RECORD;
  v_run_id uuid;
  v_user uuid := epo.require_user_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  SELECT j.id,
         j.tenant_id,
         j.status,
         COALESCE(j.script_version_id,
           (SELECT sv.id FROM epo.script_versions sv WHERE sv.script_id = j.script_id ORDER BY sv.version DESC LIMIT 1)
         ) AS effective_version
  INTO v_job
  FROM epo.jobs j
  WHERE j.id = p_job_id
    AND j.tenant_id = v_tenant
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Job % not found for tenant %', p_job_id, v_tenant;
  END IF;

  IF v_job.status <> 'active' THEN
    RAISE EXCEPTION 'Job % is not active', p_job_id;
  END IF;

  IF v_job.effective_version IS NULL THEN
    RAISE EXCEPTION 'Job % has no published script version', p_job_id;
  END IF;

  INSERT INTO epo.job_runs(job_id, tenant_id, script_version_id, trigger, requested_by)
  VALUES (v_job.id, v_tenant, v_job.effective_version, p_trigger, v_user)
  RETURNING id INTO v_run_id;

  INSERT INTO epo.job_run_targets(job_run_id, server_id, credential_id)
  SELECT v_run_id, jt.server_id, jt.credential_id
  FROM epo.job_targets jt
  WHERE jt.job_id = v_job.id;

  RETURN v_run_id;
END;
$$;
COMMENT ON FUNCTION epo.sp_enqueue_job IS 'Queues a job_run (and targets) for the caller''s tenant.';

CREATE OR REPLACE FUNCTION epo.sp_agent_claim_next()
RETURNS TABLE(id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_agent uuid := epo.require_agent_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  RETURN QUERY
  WITH candidate AS (
    SELECT jr.id
    FROM epo.job_runs jr
    WHERE jr.tenant_id = v_tenant
      AND jr.status = 'queued'
    ORDER BY jr.queued_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
  )
  UPDATE epo.job_runs jr
     SET status = 'running',
         agent_id = v_agent,
         started_at = now()
   FROM candidate c
   WHERE jr.id = c.id
  RETURNING jr.id;
END;
$$;
COMMENT ON FUNCTION epo.sp_agent_claim_next IS 'Atomically claims the next queued run for the calling agent.';

CREATE OR REPLACE FUNCTION epo.sp_update_job_run(
  p_run_id uuid,
  p_status epo.run_status,
  p_summary text DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_agent uuid := epo.require_agent_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  UPDATE epo.job_runs jr
     SET status = p_status,
         summary = COALESCE(p_summary, summary),
         completed_at = CASE WHEN p_status IN ('succeeded','failed','cancelled','abandoned') THEN now() ELSE completed_at END
   WHERE jr.id = p_run_id
     AND jr.tenant_id = v_tenant
     AND jr.agent_id = v_agent
     AND jr.status IN ('running','queued');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Run % not owned by agent %', p_run_id, v_agent;
  END IF;
END;
$$;
COMMENT ON FUNCTION epo.sp_update_job_run IS 'Allows assigned agent to update overall run status/summary.';

CREATE OR REPLACE FUNCTION epo.sp_update_job_target(
  p_job_run_id uuid,
  p_server_id uuid,
  p_status epo.run_status,
  p_exit_code integer,
  p_output_digest bytea DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_agent uuid := epo.require_agent_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  UPDATE epo.job_run_targets tgt
     SET status = p_status,
         exit_code = p_exit_code,
         output_digest = COALESCE(p_output_digest, output_digest),
         completed_at = CASE WHEN p_status IN ('succeeded','failed','cancelled','abandoned') THEN now() ELSE completed_at END
    FROM epo.job_runs jr
   WHERE tgt.job_run_id = p_job_run_id
     AND tgt.server_id = p_server_id
     AND jr.id = tgt.job_run_id
     AND jr.tenant_id = v_tenant
     AND jr.agent_id = v_agent;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Target update rejected for run % server %', p_job_run_id, p_server_id;
  END IF;
END;
$$;
COMMENT ON FUNCTION epo.sp_update_job_target IS 'Allows assigned agent to update a single target row.';

CREATE OR REPLACE FUNCTION epo.sp_append_job_log(
  p_job_run_target_id uuid,
  p_stream epo.log_stream,
  p_message text,
  p_seq bigint DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_agent uuid := epo.require_agent_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  INSERT INTO epo.job_run_logs(job_run_target_id, stream, message, seq)
  SELECT tgt.id,
         p_stream,
         p_message,
         COALESCE(p_seq,
           COALESCE((SELECT max(seq)+1 FROM epo.job_run_logs WHERE job_run_target_id = tgt.id), 0::bigint))
    FROM epo.job_run_targets tgt
    JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
   WHERE tgt.id = p_job_run_target_id
     AND jr.tenant_id = v_tenant
     AND jr.agent_id = v_agent
   LIMIT 1;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Log append rejected for target %', p_job_run_target_id;
  END IF;
END;
$$;
COMMENT ON FUNCTION epo.sp_append_job_log IS 'Streams logs for a target; enforces agent ownership.';

CREATE OR REPLACE FUNCTION epo.sp_record_agent_heartbeat(p_version text)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO epo, pg_temp
AS $$
DECLARE
  v_agent uuid := epo.require_agent_id();
  v_tenant uuid := epo.require_tenant_id();
BEGIN
  UPDATE epo.agents
     SET last_seen = now(),
         version   = COALESCE(p_version, version),
         updated_at = now()
   WHERE id = v_agent
     AND tenant_id = v_tenant;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Heartbeat rejected for agent %', v_agent;
  END IF;
END;
$$;
COMMENT ON FUNCTION epo.sp_record_agent_heartbeat IS 'Updates last_seen/version for the calling agent.';
```

```sql
-- =============================
-- Row Level Security (per table)
-- =============================

ALTER TABLE epo.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_admin_only ON epo.tenants
  FOR ALL TO app_admin
  USING (id = epo.require_tenant_id())
  WITH CHECK (id = epo.require_tenant_id());

ALTER TABLE epo.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_self_select ON epo.users
  FOR SELECT TO app_user
  USING (tenant_id = epo.require_tenant_id() AND id = epo.current_user_id());
CREATE POLICY users_admin_all ON epo.users
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.user_roles FORCE ROW LEVEL SECURITY;
CREATE POLICY user_roles_admin ON epo.user_roles
  FOR ALL TO app_admin
  USING (EXISTS (SELECT 1 FROM epo.users u WHERE u.id = user_roles.user_id AND u.tenant_id = epo.require_tenant_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM epo.users u WHERE u.id = user_roles.user_id AND u.tenant_id = epo.require_tenant_id()));

ALTER TABLE epo.agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.agents FORCE ROW LEVEL SECURITY;
CREATE POLICY agents_admin_manage ON epo.agents
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());
CREATE POLICY agents_agent_readself ON epo.agents
  FOR SELECT TO app_agent
  USING (tenant_id = epo.require_tenant_id() AND id = epo.current_agent_id());

ALTER TABLE epo.scripts ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.scripts FORCE ROW LEVEL SECURITY;
CREATE POLICY scripts_select_user ON epo.scripts
  FOR SELECT TO app_user
  USING (
    tenant_id = epo.require_tenant_id() AND (
      created_by = epo.current_user_id()
      OR visibility = 'tenant'
      OR epo.user_has_role('admin')
    )
  );
CREATE POLICY scripts_insert_user ON epo.scripts
  FOR INSERT TO app_user
  WITH CHECK (tenant_id = epo.require_tenant_id() AND created_by = epo.require_user_id());
CREATE POLICY scripts_update_user ON epo.scripts
  FOR UPDATE TO app_user
  USING (tenant_id = epo.require_tenant_id() AND created_by = epo.current_user_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND (created_by = epo.require_user_id() OR epo.user_has_role('admin')));
CREATE POLICY scripts_admin_all ON epo.scripts
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.script_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.script_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY script_versions_select_user ON epo.script_versions
  FOR SELECT TO app_user
  USING (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
        AND (s.created_by = epo.current_user_id() OR s.visibility = 'tenant' OR epo.user_has_role('admin'))
    )
  );
CREATE POLICY script_versions_insert_user ON epo.script_versions
  FOR INSERT TO app_user
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
        AND s.created_by = epo.require_user_id()
    )
  );
CREATE POLICY script_versions_update_user ON epo.script_versions
  FOR UPDATE TO app_user
  USING (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
        AND s.created_by = epo.current_user_id()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
        AND (s.created_by = epo.require_user_id() OR epo.user_has_role('admin'))
    )
  );
CREATE POLICY script_versions_select_agent ON epo.script_versions
  FOR SELECT TO app_agent
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_runs jr
      WHERE jr.script_version_id = script_versions.id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.current_agent_id()
        AND jr.status IN ('queued','running')
    )
  );
CREATE POLICY script_versions_admin_all ON epo.script_versions
  FOR ALL TO app_admin
  USING (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.scripts s
      WHERE s.id = script_versions.script_id
        AND s.tenant_id = epo.require_tenant_id()
    )
  );

ALTER TABLE epo.credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY credentials_select_user ON epo.credentials
  FOR SELECT TO app_user
  USING (tenant_id = epo.require_tenant_id() AND (created_by = epo.current_user_id() OR epo.user_has_role('admin')));
CREATE POLICY credentials_insert_user ON epo.credentials
  FOR INSERT TO app_user
  WITH CHECK (tenant_id = epo.require_tenant_id() AND created_by = epo.require_user_id());
CREATE POLICY credentials_update_user ON epo.credentials
  FOR UPDATE TO app_user
  USING (tenant_id = epo.require_tenant_id() AND created_by = epo.current_user_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND (created_by = epo.require_user_id() OR epo.user_has_role('admin')));
CREATE POLICY credentials_select_agent ON epo.credentials
  FOR SELECT TO app_agent
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.credential_id = epo.credentials.id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.current_agent_id()
        AND jr.status IN ('queued','running')
    )
  );
CREATE POLICY credentials_admin_all ON epo.credentials
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.servers FORCE ROW LEVEL SECURITY;
CREATE POLICY servers_select_user ON epo.servers
  FOR SELECT TO app_user
  USING (tenant_id = epo.require_tenant_id());
CREATE POLICY servers_insert_user ON epo.servers
  FOR INSERT TO app_user
  WITH CHECK (tenant_id = epo.require_tenant_id());
CREATE POLICY servers_update_user ON epo.servers
  FOR UPDATE TO app_user
  USING (tenant_id = epo.require_tenant_id() AND created_by = epo.current_user_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND (created_by = epo.require_user_id() OR epo.user_has_role('admin')));
CREATE POLICY servers_admin_all ON epo.servers
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.schedules ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.schedules FORCE ROW LEVEL SECURITY;
CREATE POLICY schedules_select_user ON epo.schedules
  FOR SELECT TO app_user
  USING (tenant_id = epo.require_tenant_id());
CREATE POLICY schedules_insert_user ON epo.schedules
  FOR INSERT TO app_user
  WITH CHECK (tenant_id = epo.require_tenant_id());
CREATE POLICY schedules_update_user ON epo.schedules
  FOR UPDATE TO app_user
  USING (tenant_id = epo.require_tenant_id() AND created_by = epo.current_user_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND (created_by = epo.require_user_id() OR epo.user_has_role('admin')));
CREATE POLICY schedules_admin_all ON epo.schedules
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_select_user ON epo.jobs
  FOR SELECT TO app_user
  USING (tenant_id = epo.require_tenant_id());
CREATE POLICY jobs_insert_user ON epo.jobs
  FOR INSERT TO app_user
  WITH CHECK (tenant_id = epo.require_tenant_id() AND created_by = epo.require_user_id());
CREATE POLICY jobs_update_user ON epo.jobs
  FOR UPDATE TO app_user
  USING (tenant_id = epo.require_tenant_id() AND created_by = epo.current_user_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND (created_by = epo.require_user_id() OR epo.user_has_role('admin')));
CREATE POLICY jobs_admin_all ON epo.jobs
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.job_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.job_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY job_targets_user ON epo.job_targets
  FOR ALL TO app_user
  USING (
    EXISTS (
      SELECT 1
      FROM epo.jobs j
      WHERE j.id = job_targets.job_id
        AND j.tenant_id = epo.require_tenant_id()
        AND (j.created_by = epo.current_user_id() OR epo.user_has_role('admin'))
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.jobs j
      WHERE j.id = job_targets.job_id
        AND j.tenant_id = epo.require_tenant_id()
        AND (j.created_by = epo.require_user_id() OR epo.user_has_role('admin'))
    )
  );
CREATE POLICY job_targets_admin ON epo.job_targets
  FOR ALL TO app_admin
  USING (EXISTS (SELECT 1 FROM epo.jobs j WHERE j.id = job_targets.job_id AND j.tenant_id = epo.require_tenant_id()))
  WITH CHECK (EXISTS (SELECT 1 FROM epo.jobs j WHERE j.id = job_targets.job_id AND j.tenant_id = epo.require_tenant_id()));

ALTER TABLE epo.job_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.job_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY job_runs_user_select ON epo.job_runs
  FOR SELECT TO app_user
  USING (
    tenant_id = epo.require_tenant_id()
    AND (
      requested_by = epo.current_user_id()
      OR EXISTS (
          SELECT 1
          FROM epo.jobs j
          WHERE j.id = job_runs.job_id
            AND j.created_by = epo.current_user_id()
        )
      OR epo.user_has_role('admin')
    )
  );
CREATE POLICY job_runs_agent_select ON epo.job_runs
  FOR SELECT TO app_agent
  USING (tenant_id = epo.require_tenant_id() AND agent_id = epo.current_agent_id());
CREATE POLICY job_runs_agent_update ON epo.job_runs
  FOR UPDATE TO app_agent
  USING (tenant_id = epo.require_tenant_id() AND agent_id = epo.current_agent_id())
  WITH CHECK (tenant_id = epo.require_tenant_id() AND agent_id = epo.require_agent_id());
CREATE POLICY job_runs_admin_all ON epo.job_runs
  FOR ALL TO app_admin
  USING (tenant_id = epo.require_tenant_id())
  WITH CHECK (tenant_id = epo.require_tenant_id());

ALTER TABLE epo.job_run_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.job_run_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY job_run_targets_user_select ON epo.job_run_targets
  FOR SELECT TO app_user
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND (
          jr.requested_by = epo.current_user_id()
          OR EXISTS (
              SELECT 1
              FROM epo.jobs j
              WHERE j.id = jr.job_id
                AND j.created_by = epo.current_user_id()
            )
          OR epo.user_has_role('admin')
        )
    )
  );
CREATE POLICY job_run_targets_agent_select ON epo.job_run_targets
  FOR SELECT TO app_agent
  USING (
    EXISTS (
      SELECT 1 FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.current_agent_id()
    )
  );
CREATE POLICY job_run_targets_agent_update ON epo.job_run_targets
  FOR UPDATE TO app_agent
  USING (
    EXISTS (
      SELECT 1 FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.current_agent_id()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.require_agent_id()
    )
  );
CREATE POLICY job_run_targets_admin_all ON epo.job_run_targets
  FOR ALL TO app_admin
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.job_runs jr
      WHERE jr.id = job_run_targets.job_run_id
        AND jr.tenant_id = epo.require_tenant_id()
    )
  );

ALTER TABLE epo.job_run_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE epo.job_run_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY job_run_logs_user_select ON epo.job_run_logs
  FOR SELECT TO app_user
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.id = job_run_logs.job_run_target_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND (
          jr.requested_by = epo.current_user_id()
          OR EXISTS (
              SELECT 1 FROM epo.jobs j
              WHERE j.id = jr.job_id
                AND j.created_by = epo.current_user_id()
            )
          OR epo.user_has_role('admin')
        )
    )
  );
CREATE POLICY job_run_logs_agent_insert ON epo.job_run_logs
  FOR INSERT TO app_agent
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.id = job_run_logs.job_run_target_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.require_agent_id()
    )
  );
CREATE POLICY job_run_logs_agent_select ON epo.job_run_logs
  FOR SELECT TO app_agent
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.id = job_run_logs.job_run_target_id
        AND jr.tenant_id = epo.require_tenant_id()
        AND jr.agent_id = epo.current_agent_id()
    )
  );
CREATE POLICY job_run_logs_admin_all ON epo.job_run_logs
  FOR ALL TO app_admin
  USING (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.id = job_run_logs.job_run_target_id
        AND jr.tenant_id = epo.require_tenant_id()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1
      FROM epo.job_run_targets tgt
      JOIN epo.job_runs jr ON jr.id = tgt.job_run_id
      WHERE tgt.id = job_run_logs.job_run_target_id
        AND jr.tenant_id = epo.require_tenant_id()
    )
  );
```

```sql
-- =============================
-- Grants
-- =============================

GRANT USAGE ON SCHEMA epo TO app_anon, app_user, app_admin, app_agent;
GRANT USAGE ON SCHEMA audit TO app_admin;
GRANT SELECT ON audit.audit_log TO app_admin;

GRANT SELECT ON ALL TABLES IN SCHEMA epo TO app_anon;
REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA epo FROM app_anon;

GRANT SELECT ON epo.tenants TO app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON
  epo.users, epo.user_roles, epo.agents, epo.scripts, epo.script_versions,
  epo.credentials, epo.servers, epo.schedules, epo.jobs, epo.job_targets,
  epo.job_runs, epo.job_run_targets, epo.job_run_logs
TO app_admin;

GRANT SELECT, INSERT, UPDATE ON
  epo.scripts, epo.script_versions, epo.credentials, epo.servers,
  epo.schedules, epo.jobs, epo.job_targets
TO app_user;
GRANT SELECT ON
  epo.job_runs, epo.job_run_targets, epo.job_run_logs, epo.agents
TO app_user;
GRANT EXECUTE ON FUNCTION epo.sp_enqueue_job(uuid, epo.run_trigger) TO app_user, app_admin;
GRANT EXECUTE ON FUNCTION epo.sp_register_agent(text, text, text) TO app_admin;

GRANT SELECT ON
  epo.script_versions, epo.credentials, epo.job_runs, epo.job_run_targets, epo.job_run_logs, epo.agents
TO app_agent;
GRANT INSERT, UPDATE ON epo.job_run_logs TO app_agent;
GRANT UPDATE ON epo.job_run_targets, epo.job_runs TO app_agent;
GRANT EXECUTE ON FUNCTION
  epo.sp_agent_claim_next(),
  epo.sp_update_job_run(uuid, epo.run_status, text),
  epo.sp_update_job_target(uuid, uuid, epo.run_status, integer, bytea),
  epo.sp_append_job_log(uuid, epo.log_stream, text, bigint),
  epo.sp_record_agent_heartbeat(text)
TO app_agent;

GRANT EXECUTE ON FUNCTION
  epo.require_tenant_id(), epo.require_user_id(), epo.require_agent_id(),
  epo.current_user_id(), epo.current_agent_id(), epo.current_tenant_id(),
  epo.user_has_role(text), epo.request_claims()
TO app_anon, app_user, app_admin, app_agent;
```

```sql
-- Ensure future tables inherit baseline privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT ON TABLES TO app_anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT, INSERT, UPDATE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_admin;
```

```

## 3) PostgREST Configuration

> Save as `postgrest/postgrest.conf`. Bind PostgREST to a dedicated database role (e.g. `postgrest_rest`) that has only the GRANTS listed above.

```conf
# Database connection
db-uri = "postgres://postgrest_rest:CHANGE_ME@127.0.0.1:5432/epo"

# JWT settings (HS512 recommended)
jwt-secret = "replace-with-128-hex"
jwt-aud = "epo"
role-claim-key = "role"

# Schemas exposed to the API
db-schemas = "epo"
db-anon-role = "app_anon"

# Pool tuning
server-host = "0.0.0.0"
server-port = 3001

db-pool = 10
pre-request = "epo.request_claims"  # ensures claims are parsed even for app_anon
```

> Enable `db-pre-request` only after the helper function exists. In production, supply `jwt-secret` via env var (`PGRST_JWT_SECRET`).

## 4) Auth Gateway (Node.js + Express)

Purpose: authenticate operators (local + LDAP), issue short-lived JWTs, manage agent bootstrap tokens, and expose agent public keys. The service never touches plaintext secrets and delegates all data enforcement to Postgres.

> Folder: `auth-gateway/`

### 4.1 `package.json`
```json
{
  "name": "epo-auth-gateway",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "node --watch src/index.js",
    "start": "node src/index.js"
  },
  "dependencies": {
    "argon2": "^0.30.6",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "fast-ldap-auth": "^1.0.2",
    "helmet": "^7.1.0",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.12.0",
    "pino": "^9.3.2",
    "zod": "^3.23.8"
  }
}
```

### 4.2 Environment file (`.env.example`)
```env
PORT=4000
PG_URI=postgres://postgrest_rest:CHANGE_ME@127.0.0.1:5432/epo
JWT_SECRET=generate-128-byte-hex
JWT_AUDIENCE=epo
JWT_ISSUER=epo-auth-gateway
ACCESS_TOKEN_TTL=900s
AGENT_TOKEN_TTL=300s
# Optional LDAP settings
# LDAP_URL=ldaps://dc1.domain.local:636
# LDAP_BIND_DN=CN=svc_epo,OU=Service Accounts,DC=domain,DC=local
# LDAP_BIND_PW=ChangeMe
# LDAP_SEARCH_BASE=DC=domain,DC=local
# LDAP_USERNAME_ATTRIBUTE=sAMAccountName
```

### 4.3 `src/index.js`
```js
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { LdapAuth } from 'fast-ldap-auth';
import pino from 'pino';
import { z } from 'zod';

dotenv.config();

const configSchema = z.object({
  PORT: z.coerce.number().default(4000),
  PG_URI: z.string().min(1),
  JWT_SECRET: z.string().min(64),
  JWT_AUDIENCE: z.string().default('epo'),
  JWT_ISSUER: z.string().default('epo-auth'),
  ACCESS_TOKEN_TTL: z.string().default('900s'),
  AGENT_TOKEN_TTL: z.string().default('300s'),
  LDAP_URL: z.string().optional(),
  LDAP_BIND_DN: z.string().optional(),
  LDAP_BIND_PW: z.string().optional(),
  LDAP_SEARCH_BASE: z.string().optional(),
  LDAP_USERNAME_ATTRIBUTE: z.string().default('sAMAccountName')
});

const env = configSchema.parse(process.env);
const log = pino({ level: process.env.LOG_LEVEL ?? 'info' });

const pool = new Pool({ connectionString: env.PG_URI });

const ldap = env.LDAP_URL
  ? new LdapAuth({
      url: env.LDAP_URL,
      bindDN: env.LDAP_BIND_DN,
      bindCredentials: env.LDAP_BIND_PW,
      searchBase: env.LDAP_SEARCH_BASE,
      searchFilter: `(${env.LDAP_USERNAME_ATTRIBUTE}={{username}})`,
      tlsOptions: { rejectUnauthorized: true }
    })
  : null;
if (ldap) {
  ldap.on('error', (err) => log.error({ err }, 'LDAP error'));
}

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
}));

const authBodySchema = z.object({
  tenant: z.string().min(1),
  username: z.string().min(1),
  password: z.string().min(1)
});

const agentRegistrationSchema = z.object({
  name: z.string().min(3),
  publicKeyPem: z.string().min(1),
  version: z.string().optional()
});

function mapRoles(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return value
    .replace(/[{}]/g, '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

async function loadUser(tenantSlug, username) {
  const sql = `
    SELECT u.id,
           u.tenant_id,
           t.slug,
           u.password_hash,
           u.is_active,
           u.auth_provider,
           COALESCE(array_agg(r.role) FILTER (WHERE r.role IS NOT NULL), ARRAY[]::text[]) AS app_roles
      FROM epo.users u
      JOIN epo.tenants t ON t.id = u.tenant_id
 LEFT JOIN epo.user_roles r ON r.user_id = u.id
     WHERE t.slug = $1 AND u.username = $2
  GROUP BY u.id, t.slug;
  `;
  const { rows } = await pool.query(sql, [tenantSlug, username]);
  return rows[0] ? { ...rows[0], app_roles: mapRoles(rows[0].app_roles) } : null;
}

function highestDbRole(appRoles = []) {
  return appRoles.includes('admin') ? 'app_admin' : 'app_user';
}

function issueAccessToken(user, overrides = {}) {
  const payload = {
    sub: user.id,
    tenant_id: user.tenant_id,
    tenant_slug: user.slug,
    role: overrides.role ?? highestDbRole(user.app_roles),
    app_roles: user.app_roles,
    iss: env.JWT_ISSUER,
    aud: env.JWT_AUDIENCE,
    ...overrides
  };
  return jwt.sign(payload, env.JWT_SECRET, {
    algorithm: 'HS512',
    expiresIn: overrides.expiresIn ?? env.ACCESS_TOKEN_TTL
  });
}

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'missing_auth' });
  }
  const token = auth.substring(7);
  try {
    const decoded = jwt.verify(token, env.JWT_SECRET, {
      algorithms: ['HS512'],
      audience: env.JWT_AUDIENCE,
      issuer: env.JWT_ISSUER
    });
    req.jwt = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

function requireAdmin(req, res, next) {
  const roles = Array.isArray(req.jwt?.app_roles) ? req.jwt.app_roles : [];
  if (!roles.includes('admin')) {
    return res.status(403).json({ error: 'admin_only' });
  }
  next();
}
```

```js
function issueAgentToken(agentId, tenantId, tenantSlug) {
  return jwt.sign({
    sub: agentId,
    agent_id: agentId,
    tenant_id: tenantId,
    tenant_slug: tenantSlug,
    role: 'app_agent',
    iss: env.JWT_ISSUER,
    aud: env.JWT_AUDIENCE
  }, env.JWT_SECRET, {
    algorithm: 'HS512',
    expiresIn: env.AGENT_TOKEN_TTL
  });
}

app.get('/health', (_req, res) => res.json({ ok: true }));

app.post('/auth/local', async (req, res) => {
  const parsed = authBodySchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
  }
  const { tenant, username, password } = parsed.data;
  try {
    const user = await loadUser(tenant.toLowerCase(), username);
    if (!user || user.auth_provider !== 'local' || !user.password_hash) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    if (!user.is_active) {
      return res.status(403).json({ error: 'user_disabled' });
    }
    const ok = await argon2.verify(user.password_hash, password);
    if (!ok) {
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    const token = issueAccessToken(user);
    res.json({ token, expires_in: env.ACCESS_TOKEN_TTL, roles: user.app_roles });
  } catch (err) {
    log.error({ err }, 'local auth failure');
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/ldap', async (req, res) => {
  if (!ldap) return res.status(503).json({ error: 'ldap_not_configured' });
  const parsed = authBodySchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
  }
  const { tenant, username, password } = parsed.data;
  try {
    await ldap.authenticate({ username, password });
    const user = await loadUser(tenant.toLowerCase(), username);
    if (!user || user.auth_provider !== 'ldap') {
      return res.status(403).json({ error: 'user_not_provisioned' });
    }
    if (!user.is_active) {
      return res.status(403).json({ error: 'user_disabled' });
    }
    const token = issueAccessToken(user);
    res.json({ token, expires_in: env.ACCESS_TOKEN_TTL, roles: user.app_roles });
  } catch (err) {
    log.warn({ err }, 'ldap auth failure');
    res.status(401).json({ error: 'invalid_credentials' });
  }
});

app.get('/crypto/agent-keys', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, name, public_key_pem FROM epo.agents WHERE tenant_id = $1 ORDER BY name',
      [req.jwt.tenant_id]
    );
    res.json(rows);
  } catch (err) {
    log.error({ err }, 'list agent keys failed');
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/agents', authenticate, requireAdmin, async (req, res) => {
  const parsed = agentRegistrationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
  }
  const { name, publicKeyPem, version } = parsed.data;
  try {
    const result = await pool.query(
      'SELECT epo.sp_register_agent($1,$2,$3) AS id',
      [name, publicKeyPem, version ?? null]
    );
    res.status(201).json({ id: result.rows[0].id });
  } catch (err) {
    log.error({ err }, 'agent registration failed');
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/agents/:id/token', authenticate, requireAdmin, async (req, res) => {
  const agentId = req.params.id;
  try {
    const { rows } = await pool.query(
      'SELECT id, tenant_id FROM epo.agents WHERE id = $1 AND tenant_id = $2',
      [agentId, req.jwt.tenant_id]
    );
    if (!rows.length) {
      return res.status(404).json({ error: 'agent_not_found' });
    }
    const token = issueAgentToken(agentId, req.jwt.tenant_id, req.jwt.tenant_slug);
    res.json({ token, expires_in: env.AGENT_TOKEN_TTL });
  } catch (err) {
    log.error({ err }, 'agent token issuance failed');
    res.status(500).json({ error: 'server_error' });
  }
});

app.use((err, _req, res, _next) => {
  log.error({ err }, 'unhandled error');
  res.status(500).json({ error: 'server_error' });
});

const server = app.listen(env.PORT, () => {
  log.info({ port: env.PORT }, 'Auth Gateway listening');
});

async function shutdown(signal) {
  log.info({ signal }, 'shutting down');
  server.close(() => log.info('http server closed'));
  await pool.end().catch((err) => log.error({ err }, 'pool close failed'));
  if (ldap) ldap.close();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
```

> Hash all local passwords with Argon2id (`argon2.hash(password, { type: argon2.argon2id, timeCost: 3, memoryCost: 19456 })`). LDAP provision requires pre-creating the user with `auth_provider='ldap'` and `is_active=true`.

## 5) EPO PowerShell Agent

The agent is a PowerShell 7 service that polls PostgREST with a short-lived JWT, validates content integrity, executes scripts in isolated runspaces, and streams structured logs back via stored procedures.

> Folder: `agent/`

### 5.1 `config.example.json`
```json
{
  "TenantSlug": "corp",
  "PostgrestUrl": "https://epo.example.com/rest",
  "AuthUrl": "https://epo.example.com/auth",
  "AgentId": "00000000-0000-0000-0000-000000000000",
  "BootstrapToken": "paste-admin-issued-agent-bootstrap-token",
  "PrivateKeyPath": "C:/ProgramData/EPO-Agent/agent-key.pem",
  "RequireSignedScripts": true,
  "MaxConcurrentTargets": 4,
  "PollIntervalSeconds": 5
}
```

`BootstrapToken` is the long-lived management token returned by `/agents/:id/token` (copy once into the agent host). The agent exchanges it for short-lived JWTs (`AGENT_TOKEN_TTL`).

### 5.2 `Install-Agent.ps1`
```powershell
[CmdletBinding()] param(
  [Parameter(Mandatory)] [string]$AgentName,
  [Parameter(Mandatory)] [string]$ServiceUser,
  [Parameter(Mandatory)] [securestring]$ServicePassword,
  [string]$InstallPath = 'C:\ProgramData\EPO-Agent',
  [string]$ScriptPath = (Join-Path $PSScriptRoot 'EpoAgent.ps1')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $InstallPath)) {
  New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}
Copy-Item -Path $ScriptPath -Destination (Join-Path $InstallPath 'EpoAgent.ps1') -Force

$principal = New-ScheduledTaskPrincipal -UserId $ServiceUser -LogonType Password -RunLevel Highest
$action = New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument "-NoLogo -NoProfile -File `"$InstallPath\EpoAgent.ps1`""
$settings = New-ScheduledTaskSettingsSet -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3 -ExecutionTimeLimit (New-TimeSpan -Hours 2) -MultipleInstances IgnoreNew

try {
  Unregister-ScheduledTask -TaskName $AgentName -Confirm:$false -ErrorAction SilentlyContinue
  Register-ScheduledTask -TaskName $AgentName -Action $action -Principal $principal -Settings $settings -Description 'Enterprise PowerShell Orchestrator Agent' -Password $ServicePassword
  Write-Host "Registered scheduled task '$AgentName'. Ensure config.json and private key exist at $InstallPath."
} catch {
  throw "Failed to register scheduled task: $_"
}
```

> For environments where services are preferable, wrap the script with NSSM or the Windows Service Wrapper. The scheduled-task approach avoids extra dependencies and restarts automatically on failure.

### 5.3 `EpoAgent.ps1`
```powershell
#requires -Version 7.4
param(
  [string]$ConfigPath = 'C:\ProgramData\EPO-Agent\config.json',
  [switch]$Once
)

$ErrorActionPreference = 'Stop'

function Read-AgentConfig([string]$Path) {
  if (-not (Test-Path $Path)) { throw "Config not found at $Path" }
  try {
    (Get-Content $Path -Raw | ConvertFrom-Json)
  } catch {
    throw "Invalid config JSON: $_"
  }
}

$config = Read-AgentConfig $ConfigPath

foreach ($key in 'TenantSlug','PostgrestUrl','AuthUrl','AgentId','BootstrapToken','PrivateKeyPath') {
  if (-not $config.$key) { throw "Config missing required key '$key'" }
}

$global:TokenCache = [ordered]@{ Token = $null; ExpiresAt = [DateTime]::MinValue }
$global:RsaProvider = $null
$global:Sha256 = [System.Security.Cryptography.SHA256]::Create()

function Get-JwtExpiry([string]$Token) {
  $parts = $Token.Split('.')
  if ($parts.Count -ne 3) { return (Get-Date).AddMinutes(-1) }
  $payload = $parts[1].PadRight((([math]::Ceiling($parts[1].Length / 4.0)) * 4), '=')
  $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))
  $obj = $json | ConvertFrom-Json
  if (-not $obj.exp) { return (Get-Date).AddMinutes(-1) }
  return [DateTimeOffset]::FromUnixTimeSeconds([long]$obj.exp).UtcDateTime
}

function Get-AgentToken {
  $now = (Get-Date).ToUniversalTime()
  if ($TokenCache.Token -and $TokenCache.ExpiresAt -gt $now.AddSeconds(30)) {
    return $TokenCache.Token
  }
  $uri = "{0}/agents/{1}/token" -f $config.AuthUrl.TrimEnd('/'), $config.AgentId
  $headers = @{ Authorization = "Bearer $($config.BootstrapToken)" }
  $resp = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ErrorAction Stop
  if (-not $resp.token) { throw 'Auth gateway did not return token' }
  $TokenCache.Token = $resp.token
  $TokenCache.ExpiresAt = Get-JwtExpiry $resp.token
  return $TokenCache.Token
}

function Get-AuthHeader {
  @{ Authorization = "Bearer $(Get-AgentToken)" }
}

function Invoke-EpoApi {
  param(
    [Parameter(Mandatory)][string]$Method,
    [Parameter(Mandatory)][string]$Path,
    [object]$Body,
    [switch]$Raw
  )
  $uri = if ($Path.StartsWith('http')) { $Path } else { "{0}{1}" -f $config.PostgrestUrl.TrimEnd('/'), $Path }
  $headers = Get-AuthHeader
  $json = $null
  if ($PSBoundParameters.ContainsKey('Body')) {
    $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 6 }
  }
  try {
    Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json
  } catch [System.Net.WebException] {
    if ($_.Exception.Response.StatusCode.value__ -eq 401) {
      $TokenCache.Token = $null
      $headers = Get-AuthHeader
      return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType 'application/json' -Body $json
    }
    throw
  }
}

function Convert-HexToBytes([string]$Hex) {
  if (-not $Hex) { return [byte[]]@() }
  $clean = $Hex -replace '^\\x',''
  $bytes = New-Object byte[] ($clean.Length / 2)
  for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [Convert]::ToByte($clean.Substring($i*2, 2), 16)
  }
  return $bytes
}

function Get-Rsa {
  if ($null -ne $RsaProvider) { return $RsaProvider }
  if (-not (Test-Path $config.PrivateKeyPath)) { throw "Agent private key not found at $($config.PrivateKeyPath)" }
  $pem = Get-Content $config.PrivateKeyPath -Raw
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($pem)
  $global:RsaProvider = $rsa
  return $rsa
}

function Decrypt-Secret([string]$HexCipher) {
  $cipherBytes = Convert-HexToBytes $HexCipher
  $rsa = Get-Rsa
  $plain = $rsa.Decrypt($cipherBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
  [System.Text.Encoding]::UTF8.GetString($plain)
}

function Write-RunLog {
  param(
    [guid]$TargetId,
    [ValidateSet('stdout','stderr','progress','diagnostic')][string]$Stream,
    [string]$Message
  )
  $chunks = $Message -split "(?<=\G.{1500})"
  $seq = 0
  foreach ($chunk in $chunks) {
    Invoke-EpoApi -Method Post -Path '/rpc/sp_append_job_log' -Body @{ p_job_run_target_id = $TargetId; p_stream = $Stream; p_message = $chunk; p_seq = $seq }
    $seq++
  }
}
```

```powershell
function Get-ScriptVersion([guid]$ScriptVersionId) {
  $rows = Invoke-EpoApi -Method Get -Path ("/epo.script_versions?id=eq.{0}" -f $ScriptVersionId)
  if (-not $rows) { throw "Script version $ScriptVersionId not found" }
  $rows[0]
}

function Ensure-ScriptIntegrity($scriptRow) {
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptRow.content)
  $hash = $Sha256.ComputeHash($bytes)
  $expected = (Convert-HexToBytes $scriptRow.content_sha256)
  if (-not $hash.SequenceEqual($expected)) {
    throw 'Script hash mismatch; refusing execution'
  }
  if ($config.RequireSignedScripts -and -not $scriptRow.is_signed) {
    throw 'Unsigned script rejected by policy'
  }
}

function Get-Server([guid]$ServerId) {
  $rows = Invoke-EpoApi -Method Get -Path ("/epo.servers?id=eq.{0}" -f $ServerId)
  if (-not $rows) { throw "Server $ServerId not found" }
  $rows[0]
}

function Get-CredentialRecord([guid]$CredentialId) {
  if (-not $CredentialId) { return $null }
  $rows = Invoke-EpoApi -Method Get -Path ("/epo.credentials?id=eq.{0}" -f $CredentialId)
  if (-not $rows) { throw "Credential $CredentialId not found" }
  $rows[0]
}

function New-RunCredential($record) {
  if (-not $record) { return $null }
  switch ($record.algorithm) {
    'rsa-oaep-sha256' {
      $password = Decrypt-Secret $record.cipher_text
      $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
      return New-Object System.Management.Automation.PSCredential($record.username, $secure)
    }
    'external-ref' {
      throw "External credential references require an out-of-band resolver: $($record.external_reference)"
    }
    default { throw "Unsupported credential algorithm $($record.algorithm)" }
  }
}

function Invoke-LocalScript([string]$ScriptText, [hashtable]$Parameters) {
  $ps = [powershell]::Create()
  try {
    $ps.AddScript($ScriptText) | Out-Null
    foreach ($k in $Parameters.Keys) { $ps.AddParameter($k, $Parameters[$k]) | Out-Null }
    $output = $ps.Invoke()
    $errText = $ps.Streams.Error | ForEach-Object { $_.ToString() } | Out-String
    $status = if ($ps.HadErrors) { 'failed' } else { 'succeeded' }
    [pscustomobject]@{
      Status = $status
      Output = ($output | Out-String)
      Errors = $errText
      ExitCode = if ($ps.HadErrors) { 1 } else { 0 }
    }
  } finally {
    $ps.Dispose()
  }
}

function Invoke-RemoteScript($server, $credential, [string]$ScriptText, [hashtable]$Parameters) {
  $scriptBlock = [scriptblock]::Create($ScriptText)
  $invokeParams = @{ ComputerName = $server.hostname; ScriptBlock = $scriptBlock; ErrorAction = 'Stop' }
  if ($credential) { $invokeParams.Credential = $credential }
  if ($Parameters.Count -gt 0) { $invokeParams.ArgumentList = @($Parameters) }
  try {
    $output = Invoke-Command @invokeParams
    [pscustomobject]@{
      Status = 'succeeded'
      Output = ($output | Out-String)
      Errors = ''
      ExitCode = 0
    }
  } catch {
    [pscustomobject]@{
      Status = 'failed'
      Output = ''
      Errors = $_.Exception.Message
      ExitCode = 1
    }
  }
}

function Invoke-Target($target, $scriptText) {
  $server = Get-Server $target.server_id
  $credRecord = Get-CredentialRecord $target.credential_id
  $credential = New-RunCredential $credRecord
  $parameters = if ($target.parameters) { $target.parameters | ConvertTo-Json | ConvertFrom-Json -AsHashtable } else { @{} }

  Write-RunLog -TargetId $target.id -Stream 'progress' -Message "Starting $($server.hostname)"
  if ($server.transport -eq 'local') {
    $result = Invoke-LocalScript $scriptText $parameters
  } else {
    $result = Invoke-RemoteScript $server $credential $scriptText $parameters
  }

  if ($result.Output) { Write-RunLog -TargetId $target.id -Stream 'stdout' -Message $result.Output }
  if ($result.Errors) { Write-RunLog -TargetId $target.id -Stream 'stderr' -Message $result.Errors }

  Invoke-EpoApi -Method Post -Path '/rpc/sp_update_job_target' -Body @{ 
    p_job_run_id = $target.job_run_id;
    p_server_id = $target.server_id;
    p_status = $result.Status;
    p_exit_code = $result.ExitCode;
    p_output_digest = $null
  }

  return $result.Status
}

function Process-Run([guid]$RunId) {
  $runRows = Invoke-EpoApi -Method Get -Path ("/epo.job_runs?id=eq.{0}" -f $RunId)
  if (-not $runRows) { return }
  $run = $runRows[0]
  $script = Get-ScriptVersion $run.script_version_id
  Ensure-ScriptIntegrity $script

  $targets = Invoke-EpoApi -Method Get -Path ("/epo.job_run_targets?job_run_id=eq.{0}" -f $RunId)
  if (-not $targets) {
    Invoke-EpoApi -Method Post -Path '/rpc/sp_update_job_run' -Body @{ p_run_id = $RunId; p_status = 'failed'; p_summary = 'No targets materialised' }
    return
  }

  $failures = 0
  foreach ($t in $targets) {
    try {
      $status = Invoke-Target $t $script.content
      if ($status -ne 'succeeded') { $failures++ }
    } catch {
      $failures++
      Write-RunLog -TargetId $t.id -Stream 'stderr' -Message $_.Exception.Message
      Invoke-EpoApi -Method Post -Path '/rpc/sp_update_job_target' -Body @{ 
        p_job_run_id = $t.job_run_id;
        p_server_id = $t.server_id;
        p_status = 'failed';
        p_exit_code = 1;
        p_output_digest = $null
      }
    }
  }

  $finalStatus = if ($failures -gt 0) { 'failed' } else { 'succeeded' }
  $summary = if ($failures -gt 0) { "${failures} targets failed" } else { "All targets succeeded" }
  Invoke-EpoApi -Method Post -Path '/rpc/sp_update_job_run' -Body @{ p_run_id = $RunId; p_status = $finalStatus; p_summary = $summary }
}

function Claim-NextRun {
  $resp = Invoke-EpoApi -Method Post -Path '/rpc/sp_agent_claim_next' -Body @{}
  if ($resp -is [array] -and $resp.Count -gt 0) { return [guid]$resp[0].id }
  if ($resp.id) { return [guid]$resp.id }
  return $null
}

$agentVersion = '2.0.0'

function Send-Heartbeat {
  try {
    Invoke-EpoApi -Method Post -Path '/rpc/sp_record_agent_heartbeat' -Body @{ p_version = $agentVersion } | Out-Null
  } catch {
    Write-Warning "Heartbeat failed: $_"
  }
}

while ($true) {
  Send-Heartbeat
  $runId = Claim-NextRun
  if ($runId) {
    Write-Host "Processing job_run $runId"
    try {
      Process-Run $runId
    } catch {
      Write-Warning "Run $runId failed: $_"
      Invoke-EpoApi -Method Post -Path '/rpc/sp_update_job_run' -Body @{ p_run_id = $runId; p_status = 'failed'; p_summary = $_.Exception.Message }
    }
  } elseif ($Once) {
    break
  } else {
    Start-Sleep -Seconds ($config.PollIntervalSeconds ?? 5)
  }
}
```

> The agent expects scripts to declare parameters (`param()`) when remote execution needs arguments; `target.parameters` are injected as named parameters for local runs. Extend `Invoke-RemoteScript` to leverage WinRM JEA or SSH per your environment.


## 6) React Frontend (Vite + TypeScript)

> Folder: `frontend/`

### 6.1 `package.json`
```json
{
  "name": "epo-frontend",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.7.4",
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2"
  },
  "devDependencies": {
    "@types/react": "^18.3.5",
    "@types/react-dom": "^18.3.0",
    "@types/react-router-dom": "^5.3.3",
    "typescript": "^5.6.2",
    "vite": "^5.4.7"
  }
}
```

### 6.2 `src/lib/api.ts`
```ts
import axios from 'axios';

const AUTH_URL = import.meta.env.VITE_AUTH_URL ?? 'http://localhost:4000';
const REST_URL = import.meta.env.VITE_POSTGREST_URL ?? 'http://localhost:3001';

const api = axios.create({ baseURL: REST_URL, timeout: 10000 });
let accessToken = sessionStorage.getItem('epo_access_token') ?? '';

export function setAccessToken(token: string | null) {
  accessToken = token ?? '';
  if (token) {
    sessionStorage.setItem('epo_access_token', token);
  } else {
    sessionStorage.removeItem('epo_access_token');
  }
}

api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

export async function loginLocal(tenant: string, username: string, password: string) {
  const { data } = await axios.post(`${AUTH_URL}/auth/local`, { tenant, username, password });
  setAccessToken(data.token);
  return data;
}

export async function loginLdap(tenant: string, username: string, password: string) {
  const { data } = await axios.post(`${AUTH_URL}/auth/ldap`, { tenant, username, password });
  setAccessToken(data.token);
  return data;
}

export function logout() {
  setAccessToken(null);
}

export { api };
```

### 6.3 `src/context/AuthContext.tsx`
```tsx
import React, { createContext, useContext, useMemo, useState } from 'react';
import { setAccessToken, logout as apiLogout } from '../lib/api';

type Claims = {
  sub: string;
  tenant_slug: string;
  app_roles?: string[];
  exp: number;
};

type AuthState = {
  token: string | null;
  claims: Claims | null;
  login: (token: string) => void;
  logout: () => void;
};

const AuthContext = createContext<AuthState | undefined>(undefined);

function decodeClaims(token: string): Claims | null {
  try {
    const [, payload] = token.split('.');
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setToken] = useState<string | null>(() => sessionStorage.getItem('epo_access_token'));
  const [claims, setClaims] = useState<Claims | null>(() => (token ? decodeClaims(token) : null));

  const login = (nextToken: string) => {
    setAccessToken(nextToken);
    setToken(nextToken);
    setClaims(decodeClaims(nextToken));
  };

  const logout = () => {
    apiLogout();
    setToken(null);
    setClaims(null);
  };

  const value = useMemo(() => ({ token, claims, login, logout }), [token, claims]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('Auth context missing');
  return ctx;
}
```

### 6.4 `src/main.tsx`
```tsx
import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Scripts from './pages/Scripts';
import Jobs from './pages/Jobs';
import Credentials from './pages/Credentials';

function RequireAuth({ children }: { children: JSX.Element }) {
  const { token, claims } = useAuth();
  if (!token || !claims) {
    return <Navigate to="/login" replace />;
  }
  const now = Date.now() / 1000;
  if (claims.exp && claims.exp < now) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RequireAuth><Dashboard /></RequireAuth>} />
          <Route path="/scripts" element={<RequireAuth><Scripts /></RequireAuth>} />
          <Route path="/jobs" element={<RequireAuth><Jobs /></RequireAuth>} />
          <Route path="/credentials" element={<RequireAuth><Credentials /></RequireAuth>} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  </React.StrictMode>
);
```

### 6.5 `src/pages/Login.tsx`
```tsx
import React, { useState } from 'react';
import { loginLocal, loginLdap } from '../lib/api';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState<'local' | 'ldap'>('local');
  const [tenant, setTenant] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setStatus(null);
    try {
      const fn = mode === 'local' ? loginLocal : loginLdap;
      const { token } = await fn(tenant, username, password);
      if (!token) throw new Error('No token returned');
      login(token);
      window.location.href = '/';
    } catch (err) {
      console.error(err);
      setStatus('Authentication failed');
    }
  }

  return (
    <div style={{ maxWidth: 420, margin: '10% auto', fontFamily: 'Inter, system-ui' }}>
      <h1>EPO Login</h1>
      <div style={{ marginBottom: 12 }}>
        <button type="button" onClick={() => setMode('local')} disabled={mode === 'local'}>Local</button>
        <button type="button" onClick={() => setMode('ldap')} disabled={mode === 'ldap'}>LDAP</button>
      </div>
      <form onSubmit={submit}>
        <input placeholder="tenant" value={tenant} onChange={(e) => setTenant(e.target.value)} required />
        <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        <div style={{ marginTop: 12 }}>
          <button type="submit">Sign In</button>
        </div>
      </form>
      {status && <p style={{ color: 'crimson' }}>{status}</p>}
    </div>
  );
}
```

### 6.6 `src/pages/Dashboard.tsx`
```tsx
import React from 'react';
import { useAuth } from '../context/AuthContext';

export default function Dashboard() {
  const { claims, logout } = useAuth();
  return (
    <div style={{ padding: 24 }}>
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2>Enterprise PowerShell Orchestrator</h2>
          <p>Tenant: {claims?.tenant_slug}</p>
        </div>
        <button onClick={logout}>Sign Out</button>
      </header>
      <section>
        <h3>Overview</h3>
        <ul>
          <li>Queued jobs</li>
          <li>Recent failures</li>
          <li>Agent health</li>
        </ul>
      </section>
    </div>
  );
}
```

### 6.7 `src/pages/Scripts.tsx`
```tsx
import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default function Scripts() {
  const { claims } = useAuth();
  const [scripts, setScripts] = useState<any[]>([]);
  const [name, setName] = useState('');
  const [content, setContent] = useState('');
  const [visibility, setVisibility] = useState<'private' | 'tenant'>('private');
  const [status, setStatus] = useState<string | null>(null);

  async function load() {
    const { data } = await api.get('/epo.scripts?select=id,name,visibility,created_at');
    setScripts(data);
  }

  useEffect(() => { void load(); }, []);

  async function createScript() {
    if (!claims) return;
    try {
      setStatus(null);
      const scriptRes = await api.post('/epo.scripts', {
        tenant_id: claims.tenant_id,
        name,
        visibility,
        created_by: claims.sub
      });
      const encoder = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(content));
      const hex = bytesToHex(new Uint8Array(hashBuffer));
      await api.post('/epo.script_versions', {
        script_id: scriptRes.data.id,
        version: 1,
        content,
        content_sha256: `\\x${hex}`,
        is_signed: false,
        released_by: claims.sub
      });
      setName('');
      setContent('');
      await load();
      setStatus('Script created');
    } catch (err) {
      console.error(err);
      setStatus('Create failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Scripts</h2>
      <section>
        <input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={visibility} onChange={(e) => setVisibility(e.target.value as any)}>
          <option value="private">Private</option>
          <option value="tenant">Tenant</option>
        </select>
        <textarea
          placeholder="PowerShell content"
          value={content}
          onChange={(e) => setContent(e.target.value)}
          rows={10}
          cols={80}
        />
        <div>
          <button onClick={createScript} disabled={!name || !content}>Create Script + Version</button>
        </div>
        {status && <p>{status}</p>}
      </section>
      <hr />
      <ul>
        {scripts.map((s) => (
          <li key={s.id}>{s.name} ({s.visibility})</li>
        ))}
      </ul>
    </div>
  );
}
```


### 6.8 `src/pages/Credentials.tsx`
```tsx
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { api, AUTH_URL } from '../lib/api';
import { useAuth } from '../context/AuthContext';

type AgentKey = { id: string; name: string; public_key_pem: string };

async function importAgentKey(pem: string) {
  const clean = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const buf = Uint8Array.from(atob(clean), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    'spki',
    buf,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export default function Credentials() {
  const { claims, token } = useAuth();
  const [agents, setAgents] = useState<AgentKey[]>([]);
  const [agent, setAgent] = useState<AgentKey | null>(null);
  const [name, setName] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      if (!token) return;
      const { data } = await axios.get(`${AUTH_URL}/crypto/agent-keys`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAgents(data);
    }
    void load();
  }, [token]);

  async function save() {
    if (!claims || !agent) { return; }
    try {
      const key = await importAgentKey(agent.public_key_pem);
      const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, new TextEncoder().encode(password)));
      await api.post('/epo.credentials', {
        tenant_id: claims.tenant_id,
        name,
        username,
        cipher_text: `\\x${bytesToHex(cipher)}`,
        algorithm: 'rsa-oaep-sha256',
        pubkey_fingerprint: agent.id,
        created_by: claims.sub
      });
      setStatus('Credential saved');
      setPassword('');
    } catch (err) {
      console.error(err);
      setStatus('Save failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Credentials</h2>
      <div>
        <label>Encrypt for agent: </label>
        <select value={agent?.id ?? ''} onChange={(e) => setAgent(agents.find((a) => a.id === e.target.value) ?? null)}>
          <option value="">-- select agent --</option>
          {agents.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
        </select>
      </div>
      <div style={{ display: 'grid', gap: 8, maxWidth: 360, marginTop: 16 }}>
        <input placeholder="Credential name" value={name} onChange={(e) => setName(e.target.value)} />
        <input placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} />
        <input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button onClick={save} disabled={!name || !username || !password || !agent}>Save</button>
      </div>
      {status && <p>{status}</p>}
    </div>
  );
}
```

### 6.9 `src/pages/Jobs.tsx`
```tsx
import React, { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { useAuth } from '../context/AuthContext';

export default function Jobs() {
  const { claims } = useAuth();
  const [jobs, setJobs] = useState<any[]>([]);
  const [selected, setSelected] = useState<string>('');
  const [status, setStatus] = useState<string | null>(null);

  async function load() {
    const { data } = await api.get('/epo.jobs?select=id,name,status');
    setJobs(data);
  }

  useEffect(() => { void load(); }, []);

  async function enqueue() {
    if (!selected) return;
    try {
      setStatus(null);
      await api.post('/rpc/sp_enqueue_job', { p_job_id: selected, p_trigger: 'manual' });
      setStatus('Run queued');
    } catch (err) {
      console.error(err);
      setStatus('Queue failed');
    }
  }

  return (
    <div style={{ padding: 24 }}>
      <h2>Jobs</h2>
      <select value={selected} onChange={(e) => setSelected(e.target.value)}>
        <option value="">-- select job --</option>
        {jobs.map((job) => (
          <option key={job.id} value={job.id}>{job.name} ({job.status})</option>
        ))}
      </select>
      <button onClick={enqueue} disabled={!selected || !claims}>Run Now</button>
      {status && <p>{status}</p>}
    </div>
  );
}
```

## 7) Bootstrap Script (Dev / POC)

> Folder: `infra/`

### 7.1 `bootstrap.ps1`
```powershell
[CmdletBinding()] param(
  [Parameter(Mandatory)] [string]$PgUri,
  [string]$SchemaPath = '../db/epo_schema.sql',
  [string]$PostgrestRole = 'postgrest_rest',
  [Parameter(Mandatory)] [securestring]$PostgrestPassword,
  [string]$AdminUsername,
  [string]$AdminPasswordHash  # Argon2id hash generated via Auth Gateway or argon2-cli
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $SchemaPath)) { throw "Schema file not found at $SchemaPath" }

$uri = [System.Uri]$PgUri
$pgPassword = ($uri.UserInfo.Split(':')[1])
$pgUser = $uri.UserInfo.Split(':')[0]
$pgHost = $uri.Host
$pgPort = if ($uri.Port -gt 0) { $uri.Port } else { 5432 }
$pgDb = $uri.AbsolutePath.TrimStart('/')

$env:PGPASSWORD = $pgPassword
$pgArgs = @('-h', $pgHost, '-p', $pgPort, '-U', $pgUser, '-d', $pgDb, '-v', 'ON_ERROR_STOP=1')

Write-Host 'Creating roles...'
$sqlRoles = @"
DO $$
BEGIN
  PERFORM 1 FROM pg_roles WHERE rolname = 'app_anon';
  IF NOT FOUND THEN CREATE ROLE app_anon NOLOGIN; END IF;
  PERFORM 1 FROM pg_roles WHERE rolname = 'app_user';
  IF NOT FOUND THEN CREATE ROLE app_user NOLOGIN; END IF;
  PERFORM 1 FROM pg_roles WHERE rolname = 'app_admin';
  IF NOT FOUND THEN CREATE ROLE app_admin NOLOGIN; END IF;
  PERFORM 1 FROM pg_roles WHERE rolname = 'app_agent';
  IF NOT FOUND THEN CREATE ROLE app_agent NOLOGIN; END IF;
END$$;
"@
& psql @pgArgs -c $sqlRoles | Out-Null

Write-Host "Creating PostgREST role '$PostgrestRole'..."
$tmpPw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PostgrestPassword))
$sqlRest = "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='$PostgrestRole') THEN CREATE ROLE $PostgrestRole LOGIN PASSWORD '$tmpPw'; ELSE ALTER ROLE $PostgrestRole WITH PASSWORD '$tmpPw'; END IF; END $$;"
& psql @pgArgs -c $sqlRest | Out-Null

Write-Host 'Applying schema...'
$schemaSql = Get-Content $SchemaPath -Raw
& psql @pgArgs -f $SchemaPath | Out-Null

if ($AdminUsername -and $AdminPasswordHash) {
  Write-Host "Seeding local admin user '$AdminUsername'..."
  $insertAdmin = @"
INSERT INTO epo.tenants(id, name, slug)
VALUES (uuid_generate_v4(), 'Default Tenant', 'default')
ON CONFLICT (slug) DO NOTHING;
WITH tenant AS (
  SELECT id FROM epo.tenants WHERE slug='default'
)
INSERT INTO epo.users(id, tenant_id, username, email, auth_provider, password_hash, is_active)
SELECT uuid_generate_v4(), tenant.id, '$AdminUsername', NULL, 'local', '$AdminPasswordHash', true FROM tenant
ON CONFLICT (tenant_id, username) DO NOTHING;
"@
  & psql @pgArgs -c $insertAdmin | Out-Null
  Write-Host 'Seeded default tenant + admin. Grant roles via SQL: INSERT INTO epo.user_roles ...'
} else {
  Write-Host 'Skipping admin seed (provide AdminUsername + Argon2 hash to seed).'
}

Remove-Item Env:PGPASSWORD
```

> Generate Argon2id hashes with `npx argon2-cli 'SecurePass#2024' --type argon2id --timeCost 3 --memoryCost 19456` or via the Auth Gateway helper route.

## 8) Hardening & Operational Checklist

- **Database**: enforce TLS (scram-sha-256), monitor `audit.audit_log`, enable PITR, and restrict `postgrest_rest` to IP allowlists. Run `ANALYZE` nightly and `VACUUM` audit schema regularly.
- **Auth Gateway**: terminate HTTPS at a reverse proxy with mutual TLS when possible, rotate `JWT_SECRET` quarterly, and pin outbound dependencies via `npm shrinkwrap`.
- **Agents**: run under dedicated gMSA/service accounts with `SeServiceLogonRight`, bound outbound firewall to Auth/PostgREST, store private keys in DPAPI-protected paths, and enforce code-signing via Group Policy (`Set-ExecutionPolicy AllSigned`).
- **PostgREST**: disable schema-changing verbs (already blocked by GRANTs), set `role-claim-key`, and prefer HTTPS termination with HSTS.
- **Frontend**: deploy behind reverse proxy with CSP (`default-src 'self'`), avoid localStorage for refresh tokens, and use service workers cautiously.
- **Secrets**: prefer external vault (Azure Key Vault / HashiCorp Vault) by setting credentials to `external-ref`. Provide agent plug-in to resolve secrets on execution.
- **Observability**: ship Auth Gateway logs (JSON) to SIEM, capture Postgres `log_statement='ddl'`, and alert on `audit.audit_log` spikes or failed agent heartbeats.
- **Testing**: add unit tests for stored procedures (plpgsql), contract tests for Auth Gateway, and integration suites exercising job lifecycle end-to-end.

## 9) Roadmap / Next Steps

- Build a resilient scheduler (cron parser + `next_run_at` recompute) running in Postgres or a separate worker, persisting schedule evaluations to `epo.job_runs`.
- Implement script signature enforcement (Authenticode check) server-side via a `SECURITY DEFINER` verification function rather than the agent alone.
- Integrate external vault resolvers (`external-ref`) by extending the agent to call AKV/Vault APIs based on reference type.
- Add run cancellation (`cancellation_requested` flag + agent polling) and retry policies with exponential backoff.
- Ship a reporting service: materialized views for SLA, agent availability, and credential usage.
- Harden pipeline: IaC modules (Terraform/Ansible) for repeatable deployment, GitOps for script promotion, SBOM + dependency scanning.

---


