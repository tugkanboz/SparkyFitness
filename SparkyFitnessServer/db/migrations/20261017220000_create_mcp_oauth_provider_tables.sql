-- OAuth 2.1 authorization server for MCP clients (Better Auth `jwt` +
-- `@better-auth/mcp` plugins), so a client such as the Claude mobile app can
-- connect to /mcp by signing in instead of being handed an API key.
--
-- Derived from the plugins' own schema (better-auth 1.7.4), with two local
-- conventions applied: snake_case columns (mapped in auth.ts), and `uuid` for
-- the columns that reference "user"/"session", whose ids are uuids here.
-- The tables' own ids stay `text`: the provider stores ids it derives itself
-- (for example the client-assertion jti), not only generated uuids.
--
-- Only Better Auth reads or writes these tables, through its own pool as the
-- schema owner. RLS is enabled with a deny-all policy (see rls_policies.sql) so
-- user-scoped queries on the app role can never see tokens or signing keys.

CREATE TABLE IF NOT EXISTS "jwks" (
  "id" text PRIMARY KEY,
  "public_key" text NOT NULL,
  "private_key" text NOT NULL,
  "created_at" timestamptz NOT NULL,
  "expires_at" timestamptz,
  "alg" text,
  "crv" text
);

CREATE TABLE IF NOT EXISTS "oauth_client" (
  "id" text PRIMARY KEY,
  "client_id" text NOT NULL UNIQUE,
  "client_secret" text,
  "client_discovery_id" text,
  "disabled" boolean,
  "skip_consent" boolean,
  "enable_end_session" boolean,
  "subject_type" text,
  "scopes" jsonb,
  "client_credentials_scopes" jsonb,
  "user_id" uuid REFERENCES "user" ("id") ON DELETE CASCADE,
  "created_at" timestamptz,
  "updated_at" timestamptz,
  "name" text,
  "uri" text,
  "icon" text,
  "contacts" jsonb,
  "tos" text,
  "policy" text,
  "software_id" text,
  "software_version" text,
  "software_statement" text,
  "redirect_uris" jsonb NOT NULL,
  "post_logout_redirect_uris" jsonb,
  "backchannel_logout_uri" text,
  "backchannel_logout_session_required" boolean,
  "token_endpoint_auth_method" text,
  "application_type" text,
  "jwks" text,
  "jwks_uri" text,
  "grant_types" jsonb,
  "response_types" jsonb,
  "require_pkce" boolean,
  "dpop_bound_access_tokens" boolean,
  "reference_id" text,
  "metadata" jsonb
);

CREATE TABLE IF NOT EXISTS "oauth_resource" (
  "id" text PRIMARY KEY,
  "identifier" text NOT NULL UNIQUE,
  "name" text NOT NULL,
  "access_token_ttl" integer,
  "refresh_token_ttl" integer,
  "signing_algorithm" text,
  "signing_key_id" text,
  "allowed_scopes" jsonb,
  "custom_claims" jsonb,
  "dpop_bound_access_tokens_required" boolean,
  "disabled" boolean,
  "created_at" timestamptz,
  "updated_at" timestamptz,
  "policy_version" integer,
  "metadata" jsonb
);

CREATE TABLE IF NOT EXISTS "oauth_client_resource" (
  "id" text PRIMARY KEY,
  "client_id" text NOT NULL REFERENCES "oauth_client" ("client_id") ON DELETE CASCADE,
  "resource_id" text NOT NULL REFERENCES "oauth_resource" ("identifier") ON DELETE CASCADE,
  "metadata" jsonb,
  "created_at" timestamptz
);

CREATE TABLE IF NOT EXISTS "oauth_refresh_token" (
  "id" text PRIMARY KEY,
  "token" text NOT NULL UNIQUE,
  "client_id" text NOT NULL REFERENCES "oauth_client" ("client_id") ON DELETE CASCADE,
  "session_id" uuid REFERENCES "session" ("id") ON DELETE SET NULL,
  "user_id" uuid NOT NULL REFERENCES "user" ("id") ON DELETE CASCADE,
  "reference_id" text,
  "authorization_code_id" text,
  "resources" jsonb,
  "requested_user_info_claims" jsonb,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL,
  "revoked" timestamptz,
  "rotated_at" timestamptz,
  "rotation_replay_response" text,
  "rotation_replay_expires_at" timestamptz,
  "auth_time" timestamptz,
  "confirmation" jsonb,
  "scopes" jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS "oauth_access_token" (
  "id" text PRIMARY KEY,
  "token" text NOT NULL UNIQUE,
  "client_id" text NOT NULL REFERENCES "oauth_client" ("client_id") ON DELETE CASCADE,
  "session_id" uuid REFERENCES "session" ("id") ON DELETE SET NULL,
  "user_id" uuid REFERENCES "user" ("id") ON DELETE CASCADE,
  "reference_id" text,
  "authorization_code_id" text,
  "resources" jsonb,
  "requested_user_info_claims" jsonb,
  "refresh_id" text REFERENCES "oauth_refresh_token" ("id") ON DELETE CASCADE,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL,
  "revoked" timestamptz,
  "confirmation" jsonb,
  "scopes" jsonb NOT NULL
);

CREATE TABLE IF NOT EXISTS "oauth_consent" (
  "id" text PRIMARY KEY,
  "client_id" text NOT NULL REFERENCES "oauth_client" ("client_id") ON DELETE CASCADE,
  "user_id" uuid REFERENCES "user" ("id") ON DELETE CASCADE,
  "reference_id" text,
  "resources" jsonb,
  "requested_user_info_claims" jsonb,
  "scopes" jsonb NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS "oauth_client_assertion" (
  "id" text PRIMARY KEY,
  "expires_at" timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_oauth_client_user_id" ON "oauth_client" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_client_resource_client_id" ON "oauth_client_resource" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_client_resource_resource_id" ON "oauth_client_resource" ("resource_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_refresh_token_client_id" ON "oauth_refresh_token" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_refresh_token_session_id" ON "oauth_refresh_token" ("session_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_refresh_token_user_id" ON "oauth_refresh_token" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_refresh_token_authorization_code_id" ON "oauth_refresh_token" ("authorization_code_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_access_token_client_id" ON "oauth_access_token" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_access_token_session_id" ON "oauth_access_token" ("session_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_access_token_user_id" ON "oauth_access_token" ("user_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_access_token_authorization_code_id" ON "oauth_access_token" ("authorization_code_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_access_token_refresh_id" ON "oauth_access_token" ("refresh_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_consent_client_id" ON "oauth_consent" ("client_id");
CREATE INDEX IF NOT EXISTS "idx_oauth_consent_user_id" ON "oauth_consent" ("user_id");

