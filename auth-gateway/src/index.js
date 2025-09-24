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
