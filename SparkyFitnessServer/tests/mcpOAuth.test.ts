import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import {
  looksLikeJwt,
  mcpAuthChallenge,
  mcpIssuer,
  mcpResourceUrl,
  resetMcpJwksCache,
  verifyMcpAccessToken,
} from '../utils/mcpOAuth.js';

const ORIGIN = 'https://fit.example.com';

async function setup() {
  const { publicKey, privateKey } = await generateKeyPair('ES256');
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'ES256' };
  const sign = (claims: { iss?: string; aud?: string; sub?: string }) =>
    new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
      .setIssuer(claims.iss ?? mcpIssuer())
      .setAudience(claims.aud ?? mcpResourceUrl())
      .setSubject(claims.sub ?? 'user-1')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
  return { loadJwks: async () => ({ keys: [jwk] }), sign };
}

describe('mcpOAuth', () => {
  const saved = { ...process.env };
  beforeEach(() => {
    process.env.SPARKY_FITNESS_FRONTEND_URL = `${ORIGIN}/`;
    delete process.env.BETTER_AUTH_URL;
    resetMcpJwksCache();
  });
  afterEach(() => {
    process.env = { ...saved };
  });

  it('derives the resource, issuer and challenge from the frontend URL', () => {
    expect(mcpResourceUrl()).toBe(`${ORIGIN}/mcp`);
    expect(mcpIssuer()).toBe(`${ORIGIN}/api/auth`);
    expect(mcpAuthChallenge('invalid_token')).toBe(
      `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp", error="invalid_token"`
    );
  });

  it('tells JWTs apart from API keys and session tokens', () => {
    expect(looksLikeJwt('eyJhbGciOi.eyJzdWIi.c2ln')).toBe(true);
    expect(looksLikeJwt('a'.repeat(64))).toBe(false);
    expect(looksLikeJwt('sessiontoken.signature')).toBe(false);
  });

  it('accepts a token for this resource and returns its subject', async () => {
    const { loadJwks, sign } = await setup();
    await expect(verifyMcpAccessToken(await sign({}), loadJwks)).resolves.toBe(
      'user-1'
    );
  });

  it('rejects a token for another audience or issuer', async () => {
    const { loadJwks, sign } = await setup();
    await expect(
      verifyMcpAccessToken(await sign({ aud: 'https://other/mcp' }), loadJwks)
    ).rejects.toThrow();
    await expect(
      verifyMcpAccessToken(await sign({ iss: 'https://evil' }), loadJwks)
    ).rejects.toThrow();
  });
});
