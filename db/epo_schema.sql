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
