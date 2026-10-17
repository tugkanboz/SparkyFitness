/**
 * Continuing an OAuth authorization (an MCP client such as the Claude app
 * connecting to this server) across the login page.
 *
 * When the server's authorize endpoint finds no session it redirects to
 * `/login?<authorization request>&sig=...`. Signing in through any of the login
 * methods ends on the home page, so the request is kept in sessionStorage and
 * replayed against the authorize endpoint once a user is signed in. With a
 * session, authorize then moves on to the consent page.
 */

const STORAGE_KEY = 'sparky.pendingOAuthAuthorize';
const MAX_AGE_MS = 10 * 60 * 1000;

// Parameters the server adds when it signs the redirect to the login page.
// They belong to that redirect, not to the authorization request.
const SIGNING_PARAMS = ['sig', 'exp', 'ba_iat', 'ba_pl', 'ba_param'];

/**
 * The authorize URL to replay for a login-page query string, or null when the
 * query is not a signed authorization request.
 */
export function authorizeUrlFromLoginQuery(search: string): string | null {
  const params = new URLSearchParams(search);
  if (!params.has('sig') || !params.has('client_id')) return null;
  for (const name of SIGNING_PARAMS) params.delete(name);
  // `prompt=login` is what sent a signed-in user here; replaying it would loop.
  params.delete('prompt');
  return `/api/auth/oauth2/authorize?${params.toString()}`;
}

export function rememberPendingOAuthAuthorize(search: string): void {
  const url = authorizeUrlFromLoginQuery(search);
  if (!url) return;
  try {
    sessionStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({ url, savedAt: Date.now() })
    );
  } catch {
    // Storage unavailable (private mode): the flow can still be restarted
    // from the client.
  }
}

/** Returns and clears a pending authorize URL that is still fresh. */
export function takePendingOAuthAuthorize(): string | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    sessionStorage.removeItem(STORAGE_KEY);
    const { url, savedAt } = JSON.parse(raw) as {
      url?: unknown;
      savedAt?: unknown;
    };
    if (
      typeof url !== 'string' ||
      !url.startsWith('/api/auth/oauth2/authorize?') ||
      typeof savedAt !== 'number' ||
      Date.now() - savedAt > MAX_AGE_MS
    ) {
      return null;
    }
    return url;
  } catch {
    return null;
  }
}
