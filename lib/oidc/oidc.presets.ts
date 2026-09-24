import type { OidcProviderConfig } from '../interfaces/oidc-provider.interface.js';

type Credentials = { clientId: string; clientSecret: string };

export function google(credentials: Credentials): OidcProviderConfig {
  return { issuer: 'https://accounts.google.com', ...credentials };
}

/**
 * Microsoft Entra ID, single tenant. Multi-tenant endpoints (`common`,
 * `organizations`, `consumers`) publish a templated issuer
 * (`https://login.microsoftonline.com/{tenantid}/v2.0`) that needs
 * per-token issuer validation against `tid`; not supported in this POC.
 */
export function microsoft({ tenant, ...credentials }: Credentials & { tenant: string }): OidcProviderConfig {
  if (['common', 'organizations', 'consumers'].includes(tenant)) {
    throw new Error(`microsoft(): multi-tenant '${tenant}' is not supported; pass a tenant id or domain.`);
  }
  return { issuer: `https://login.microsoftonline.com/${tenant}/v2.0`, ...credentials };
}

/**
 * GitHub is OAuth 2.0, not OIDC: no discovery, no ID token. The profile
 * comes from `GET /user`, and the email from `GET /user/emails` (primary and
 * verified only), since the public profile email is user-controlled.
 */
export function github(credentials: Credentials): OidcProviderConfig {
  return {
    kind: 'oauth2',
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    userinfoEndpoint: 'https://api.github.com/user',
    scopes: ['read:user', 'user:email'],
    ...credentials,
    async profile(user, { provider, fetchJson }) {
      if (typeof user?.id !== 'number' && typeof user?.id !== 'string') {
        throw new Error('unexpected GitHub user');
      }

      const emails: { email: string; primary: boolean; verified: boolean }[] = await fetchJson(
        `${this.userinfoEndpoint}/emails`,
      );
      const primary = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified) : undefined;

      return {
        provider,
        subject: String(user.id),
        email: primary?.email,
        emailVerified: !!primary,
        name: user.name ?? user.login,
        picture: user.avatar_url,
        claims: user,
      };
    },
  };
}
