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
-- Ensure future tables inherit baseline privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT ON TABLES TO app_anon;
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT, INSERT, UPDATE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA epo GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_admin;

## 3) PostgREST Configuration

> Save as `postgrest/postgrest.conf`. Bind PostgREST to a dedicated database role (e.g. `postgrest_rest`) that has only the GRANTS listed above.

> Enable `db-pre-request` only after the helper function exists. In production, supply `jwt-secret` via env var (`PGRST_JWT_SECRET`).

## 4) Auth Gateway (Node.js + Express)

Purpose: authenticate operators (local + LDAP), issue short-lived JWTs, manage agent bootstrap tokens, and expose agent public keys. The service never touches plaintext secrets and delegates all data enforcement to Postgres.

> Folder: `auth-gateway/`

### 4.1 `package.json`

### 4.2 Environment file (`.env.example`)

### 4.3 `src/index.js`


> Hash all local passwords with Argon2id (`argon2.hash(password, { type: argon2.argon2id, timeCost: 3, memoryCost: 19456 })`). LDAP provision requires pre-creating the user with `auth_provider='ldap'` and `is_active=true`.

## 5) EPO PowerShell Agent

The agent is a PowerShell 7 service that polls PostgREST with a short-lived JWT, validates content integrity, executes scripts in isolated runspaces, and streams structured logs back via stored procedures.

> Folder: `agent/`

### 5.1 `config.example.json`

`BootstrapToken` is the long-lived management token returned by `/agents/:id/token` (copy once into the agent host). The agent exchanges it for short-lived JWTs (`AGENT_TOKEN_TTL`).

### 5.2 `Install-Agent.ps1`

> For environments where services are preferable, wrap the script with NSSM or the Windows Service Wrapper. The scheduled-task approach avoids extra dependencies and restarts automatically on failure.

### 5.3 `EpoAgent.ps1`


> The agent expects scripts to declare parameters (`param()`) when remote execution needs arguments; `target.parameters` are injected as named parameters for local runs. Extend `Invoke-RemoteScript` to leverage WinRM JEA or SSH per your environment.


## 6) React Frontend (Vite + TypeScript)

> Folder: `frontend/`

### 6.1 `package.json`

### 6.2 `src/lib/api.ts`

### 6.3 `src/context/AuthContext.tsx`

### 6.4 `src/main.tsx`

### 6.5 `src/pages/Login.tsx`

### 6.6 `src/pages/Dashboard.tsx`

### 6.7 `src/pages/Scripts.tsx`


### 6.8 `src/pages/Credentials.tsx`

### 6.9 `src/pages/Jobs.tsx`

## 7) Bootstrap Script (Dev / POC)

> Folder: `infra/`

### 7.1 `bootstrap.ps1`
