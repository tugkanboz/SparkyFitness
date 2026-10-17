import type { NextFunction, Request, Response } from 'express';
import type { JSONWebKeySet } from 'jose';
import { log } from '../config/logging.js';
import { auth } from '../auth.js';
import { dbContextStorage } from '../db/poolManager.js';
import userRepository from '../models/userRepository.js';
import {
  looksLikeJwt,
  mcpAuthChallenge,
  mcpIssuer,
  verifyMcpAccessToken,
} from '../utils/mcpOAuth.js';
import { authenticate } from './authMiddleware.js';

// The jwt plugin's /jwks endpoint, called in-process through the auth handler
// (no request leaves the server). Its endpoint is not on the inferred
// `auth.api` type, and the handler also gives the exact public serialization.
const loadJwks = async (): Promise<JSONWebKeySet> => {
  const response = await auth.handler(new Request(`${mcpIssuer()}/jwks`));
  if (!response.ok) {
    throw new Error(`Could not load signing keys (${response.status})`);
  }
  return (await response.json()) as JSONWebKeySet;
};

function bearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim() || null;
}

/**
 * Authentication for the `/mcp` mount.
 *
 * - A Bearer JWT is an access token from the MCP OAuth authorization server
 *   (auth.ts `mcp()` plugin): it is verified against this server's signing
 *   keys, issuer and the `/mcp` audience, and acts as its owner.
 * - Anything else (API key, session) goes through the normal `authenticate`.
 *
 * Every 401 carries an RFC 9728 `WWW-Authenticate` challenge pointing at the
 * protected resource metadata, which is how an MCP client learns it can start
 * the OAuth flow instead of asking for a key.
 */
export async function mcpAuthenticate(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const originalStatus = res.status.bind(res);
  res.status = (code: number) => {
    if (code === 401 && !res.getHeader('WWW-Authenticate')) {
      res.setHeader('WWW-Authenticate', mcpAuthChallenge());
    }
    return originalStatus(code);
  };

  const token = bearerToken(req);
  if (!token || !looksLikeJwt(token)) {
    return authenticate(req, res, next);
  }

  let userId: string;
  try {
    userId = await verifyMcpAccessToken(token, loadJwks);
  } catch (error) {
    log('warn', 'MCP OAuth: access token rejected:', error);
    res.setHeader('WWW-Authenticate', mcpAuthChallenge('invalid_token'));
    return res.status(401).json({ error: 'Invalid or expired access token.' });
  }

  const user = await userRepository.findUserById(userId);
  if (!user) {
    res.setHeader('WWW-Authenticate', mcpAuthChallenge('invalid_token'));
    return res.status(401).json({ error: 'Invalid or expired access token.' });
  }

  // An OAuth token always acts as its owner: no delegation or context switch,
  // and full (read/write) scope like an unscoped API key.
  req.authenticatedUserId = userId;
  req.originalUserId = userId;
  req.activeUserId = userId;
  req.userId = userId;
  req.user = user;
  req.apiKeyReadOnly = false;

  try {
    await userRepository.ensureUserInitialization(userId, user.full_name);
  } catch (error) {
    log('error', `Lazy Initialization failed for user ${userId}:`, error);
  }
  return dbContextStorage.run({ authenticatedUserId: userId }, next);
}
