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

