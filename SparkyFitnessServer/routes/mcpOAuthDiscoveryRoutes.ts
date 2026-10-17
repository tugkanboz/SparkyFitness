import express, { type Request, type Response } from 'express';
import {
  oauthProviderAuthServerMetadata,
  oauthProviderOpenIdConfigMetadata,
} from '@better-auth/oauth-provider';
import { auth } from '../auth.js';
import { log } from '../config/logging.js';
import { mcpIssuer, mcpResourceUrl } from '../utils/mcpOAuth.js';

/**
 * OAuth discovery documents for MCP clients, served at the origin root.
 *
 * Better Auth mounts under /api/auth, but discovery is rooted at the origin:
 * RFC 9728 protected resource metadata for `/mcp` lives at
 * `/.well-known/oauth-protected-resource/mcp`, and RFC 8414 metadata for the
 * issuer `<origin>/api/auth` at `/.well-known/oauth-authorization-server/api/auth`.
 * Clients probe both the path-suffixed and the bare form, so both are served.
 * Only these exact paths are handled, leaving the rest of `/.well-known/*`
 * (for example an ACME http-01 challenge) untouched.
 */
const router = express.Router();

const protectedResourceMetadata = (_req: Request, res: Response) => {
  res.set('Cache-Control', 'public, max-age=300');
  res.json({
    resource: mcpResourceUrl(),
    authorization_servers: [mcpIssuer()],
    bearer_methods_supported: ['header'],
  });
};

// The provider's own helpers build these documents. Its endpoints are
// server-only (not reachable through /api/auth over HTTP) and are not on the
// inferred `auth.api` type, so the helpers get `auth` through the narrow shape
// they declare. The fetch Request they take is built in-process.
type ProviderAuth = Parameters<typeof oauthProviderAuthServerMetadata>[0] &
  Parameters<typeof oauthProviderOpenIdConfigMetadata>[0];
const providerAuth = auth as unknown as ProviderAuth;

const fromProvider =
  (handler: (request: globalThis.Request) => Promise<globalThis.Response>) =>
  async (req: Request, res: Response) => {
    try {
      const response = await handler(
        new globalThis.Request(`${mcpIssuer()}${req.path}`)
      );
      res.status(response.status);
      response.headers.forEach((value, key) => res.setHeader(key, value));
      res.send(await response.text());
    } catch (error) {
      log('error', 'MCP OAuth: discovery metadata failed:', error);
      res.status(500).json({ error: 'server_error' });
    }
  };

const authServerMetadata = fromProvider(
  oauthProviderAuthServerMetadata(providerAuth)
);
const openIdConfiguration = fromProvider(
  oauthProviderOpenIdConfigMetadata(providerAuth)
);

router.get(
  [
    '/.well-known/oauth-protected-resource',
    '/.well-known/oauth-protected-resource/mcp',
  ],
  protectedResourceMetadata
);
router.get(
  [
    '/.well-known/oauth-authorization-server',
    '/.well-known/oauth-authorization-server/api/auth',
  ],
  authServerMetadata
);
router.get(
  [
    '/.well-known/openid-configuration',
    '/.well-known/openid-configuration/api/auth',
  ],
  openIdConfiguration
);

export default router;
