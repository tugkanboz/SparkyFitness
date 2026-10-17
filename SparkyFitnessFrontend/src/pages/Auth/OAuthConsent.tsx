import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { useAuth } from '@/hooks/useAuth';
import {
  useOAuthConsentMutation,
  useOAuthPublicClientQuery,
} from '@/hooks/Auth/useAuth';
import { getErrorMessage } from '@/utils/api';

/**
 * Consent page for the MCP OAuth authorization server: an MCP client (for
 * example the Claude app) asks to act on the signed-in user's data, and the
 * user allows or denies it. The server redirects here with a signed query,
 * which is sent back unchanged with the answer.
 */
const OAuthConsent = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { user, loading: authLoading } = useAuth();
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const search = window.location.search;
  const params = new URLSearchParams(search);
  const clientId = params.get('client_id');
  const scopes = (params.get('scope') ?? '').split(' ').filter(Boolean);

  useEffect(() => {
    // Signed out (or the session expired) mid-flow: the login page keeps the
    // signed request and brings the user back here after sign-in.
    if (!authLoading && !user) navigate(`/login${search}`, { replace: true });
  }, [authLoading, user, navigate, search]);

  const { data: client } = useOAuthPublicClientQuery(user ? clientId : null);
  const { mutateAsync: consent } = useOAuthConsentMutation();

  const answer = async (accept: boolean) => {
    setSubmitting(true);
    setErrorMessage(null);
    const failed = t(
      'oauthConsent.failed',
      'The request could not be completed. Start the connection again from the app.'
    );
    try {
      const result = await consent({
        accept,
        oauthQuery: window.location.search.replace(/^\?/, ''),
      });
      const next = result?.url ?? result?.redirect_uri;
      if (next) {
        window.location.href = next;
        return;
      }
      setErrorMessage(failed);
    } catch (err: unknown) {
      setErrorMessage(getErrorMessage(err) || failed);
    }
    setSubmitting(false);
  };

  const scopeLabel = (scope: string) => {
    switch (scope) {
      case 'openid':
        return t('oauthConsent.scope.openid', 'Confirm who you are');
      case 'profile':
        return t('oauthConsent.scope.profile', 'See your name');
      case 'email':
        return t('oauthConsent.scope.email', 'See your email address');
      case 'offline_access':
        return t(
          'oauthConsent.scope.offlineAccess',
          'Stay connected until you remove it'
        );
      default:
        return scope;
    }
  };

  const clientName =
    client?.client_name ?? t('oauthConsent.unknownApp', 'An application');

  if (!clientId) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
        <p>
          {t(
            'oauthConsent.invalid',
            'This authorization link is incomplete. Start the connection again from the app.'
          )}
        </p>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 py-12 px-4 sm:px-6 lg:px-8">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="flex items-center justify-center mb-4">
            <img
              src="/images/SparkyFitness.webp"
              alt="SparkyFitness"
              className="h-10 w-10"
            />
          </div>
          <CardTitle>
            {t('oauthConsent.title', 'Allow {{app}} to use your account?', {
              app: clientName,
            })}
          </CardTitle>
          <CardDescription>
            {t(
              'oauthConsent.description',
              '{{app}} will be able to read and change your SparkyFitness data (diary, exercise, measurements and more) as {{email}}.',
              { app: clientName, email: user?.email ?? '' }
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {scopes.length > 0 && (
            <ul className="list-disc pl-5 text-sm text-muted-foreground space-y-1">
              {scopes.map((scope) => (
                <li key={scope}>{scopeLabel(scope)}</li>
              ))}
            </ul>
          )}
          {client?.client_uri && (
            <p className="text-xs text-muted-foreground break-all">
              {client.client_uri}
            </p>
          )}
          {errorMessage && (
            <p className="text-sm text-destructive">{errorMessage}</p>
          )}
          <div className="flex gap-2">
            <Button
              variant="outline"
              className="flex-1"
              disabled={submitting}
              onClick={() => answer(false)}
            >
              {t('oauthConsent.deny', 'Deny')}
            </Button>
            <Button
              className="flex-1"
              disabled={submitting || authLoading || !user}
              onClick={() => answer(true)}
            >
              {t('oauthConsent.allow', 'Allow')}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default OAuthConsent;
