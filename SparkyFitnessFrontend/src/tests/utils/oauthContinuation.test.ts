import {
  authorizeUrlFromLoginQuery,
  rememberPendingOAuthAuthorize,
  takePendingOAuthAuthorize,
} from '@/utils/oauthContinuation';

describe('oauthContinuation', () => {
  beforeEach(() => sessionStorage.clear());

  it('rebuilds the authorize request without the signing parameters', () => {
    const url = authorizeUrlFromLoginQuery(
      '?client_id=abc&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&state=s&prompt=login&exp=1&ba_iat=2&ba_param=client_id&sig=xyz'
    );
    expect(url).toBe(
      '/api/auth/oauth2/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fclaude.ai%2Fcb&state=s'
    );
  });

  it('ignores a login page that is not part of an authorization', () => {
    expect(authorizeUrlFromLoginQuery('?redirect=/diary')).toBeNull();
    rememberPendingOAuthAuthorize('?redirect=/diary');
    expect(takePendingOAuthAuthorize()).toBeNull();
  });

  it('hands the pending request back once, while it is fresh', () => {
    rememberPendingOAuthAuthorize('?client_id=abc&sig=xyz');
    expect(takePendingOAuthAuthorize()).toBe(
      '/api/auth/oauth2/authorize?client_id=abc'
    );
    expect(takePendingOAuthAuthorize()).toBeNull();
  });

  it('drops a stale request', () => {
    sessionStorage.setItem(
      'sparky.pendingOAuthAuthorize',
      JSON.stringify({
        url: '/api/auth/oauth2/authorize?client_id=abc',
        savedAt: Date.now() - 11 * 60 * 1000,
      })
    );
    expect(takePendingOAuthAuthorize()).toBeNull();
  });
});
