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
