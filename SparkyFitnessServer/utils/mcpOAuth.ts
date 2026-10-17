import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from 'jose';

/**
 * Shared constants for the MCP OAuth authorization server (`mcp()` plugin in
 * auth.ts) and for verifying the access tokens it issues on `/mcp`.
 *
 * Everything is derived from SPARKY_FITNESS_FRONTEND_URL because MCP clients
 * reach the server through the frontend's nginx, which proxies `/mcp`,
 * `/api/auth/*` and the OAuth discovery documents.
 */

function publicOrigin(): string {
  const raw = process.env.SPARKY_FITNESS_FRONTEND_URL ?? '';
  const url = raw.startsWith('http') ? raw : `https://${raw}`;
  return url.replace(/\/+$/, '');
}

/** The MCP protected resource identifier tokens are audience-bound to. */
export function mcpResourceUrl(): string {
  return `${publicOrigin()}/mcp`;
}

/**
 * The authorization server issuer. Better Auth's issuer is its base URL, which
 * auth.ts sets to the frontend origin plus `/api/auth` unless BETTER_AUTH_URL
 * overrides it.
 */
export function mcpIssuer(): string {
  return (
    process.env.BETTER_AUTH_URL?.replace(/\/+$/, '') ||
    `${publicOrigin()}/api/auth`
  );
}

/** RFC 9728 metadata URL advertised in `WWW-Authenticate` challenges. */
export function mcpResourceMetadataUrl(): string {
  return `${publicOrigin()}/.well-known/oauth-protected-resource/mcp`;
}

export function mcpAuthChallenge(error?: 'invalid_token'): string {
  const parts = [`resource_metadata="${mcpResourceMetadataUrl()}"`];
  if (error) parts.push(`error="${error}"`);
  return `Bearer ${parts.join(', ')}`;
}

/**
 * True for a compact JWS (`header.payload.signature` with a JSON header), the
 * shape of an MCP OAuth access token. API keys have no dots, and Better Auth
 * session tokens carry at most one (`token.signature`).
 */
export function looksLikeJwt(token: string): boolean {
  const parts = token.split('.');
  return parts.length === 3 && token.startsWith('eyJ');
}

type JwksLoader = () => Promise<JSONWebKeySet>;

let cachedKeySet: ReturnType<typeof createLocalJWKSet> | null = null;
let cachedAt = 0;
const JWKS_CACHE_MS = 10 * 60 * 1000;

async function keySet(loadJwks: JwksLoader, force: boolean) {
  if (!cachedKeySet || force || Date.now() - cachedAt > JWKS_CACHE_MS) {
    cachedKeySet = createLocalJWKSet(await loadJwks());
    cachedAt = Date.now();
  }
  return cachedKeySet;
}

/**
 * Verifies an MCP access token against this server's own signing keys and
 * returns the user id (`sub`). The keys are read in-process (no HTTP round trip
 * through the public URL) and cached; a token signed with a key the cache has
 * not seen yet (after a rotation) reloads them once.
 */
export async function verifyMcpAccessToken(
  token: string,
  loadJwks: JwksLoader
): Promise<string> {
  const options = { issuer: mcpIssuer(), audience: mcpResourceUrl() };
  let result;
  try {
    result = await jwtVerify(token, await keySet(loadJwks, false), options);
  } catch (error) {
    if ((error as { code?: string }).code !== 'ERR_JWKS_NO_MATCHING_KEY') {
      throw error;
    }
    result = await jwtVerify(token, await keySet(loadJwks, true), options);
  }
  const sub = result.payload.sub;
  if (!sub) throw new Error('MCP access token has no subject');
  return sub;
}

/** Test hook: forget cached signing keys. */
export function resetMcpJwksCache(): void {
  cachedKeySet = null;
  cachedAt = 0;
}
