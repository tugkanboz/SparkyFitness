import { useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import {
  rememberPendingOAuthAuthorize,
  takePendingOAuthAuthorize,
} from '@/utils/oauthContinuation';

/**
 * Resumes an OAuth authorization that was interrupted by the login page (see
 * utils/oauthContinuation.ts). Renders nothing.
 */
export function OAuthContinuation() {
  const location = useLocation();
  const { user, loading } = useAuth();

  useEffect(() => {
    if (location.pathname.startsWith('/login')) {
      rememberPendingOAuthAuthorize(location.search);
    }
  }, [location.pathname, location.search]);

  useEffect(() => {
    if (loading || !user) return;
    const url = takePendingOAuthAuthorize();
    if (url) window.location.replace(url);
  }, [user, loading, location.pathname]);

  return null;
}
