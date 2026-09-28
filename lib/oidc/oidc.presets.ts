import type { OidcProviderConfig } from '../interfaces/oidc-provider.interface.js';

type Credentials = { clientId: string; clientSecret: string };

export function google(credentials: Credentials): OidcProviderConfig {
  return { issuer: 'https://accounts.google.com', ...credentials };
}

const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Microsoft Entra ID, single tenant, by its tenant id (a GUID). Whatever
 * name discovery is asked with, a domain included, Entra publishes the
 * issuer of the tenant id, which must match exactly. Multi-tenant endpoints
 * (`common`, `organizations`, `consumers`) publish a templated issuer
 * (`https://login.microsoftonline.com/{tenantid}/v2.0`) that needs per-token
 * issuer validation against `tid`; not supported.
 */
export function microsoft({ tenant, ...credentials }: Credentials & { tenant: string }): OidcProviderConfig {
  if (typeof tenant !== 'string' || !TENANT_ID.test(tenant)) {
    throw new Error(
      `microsoft(): pass the tenant id, a GUID (Entra admin center, Overview), not ${JSON.stringify(tenant)}: ` +
        'for a domain, and for the multi-tenant common, organizations and consumers, Microsoft publishes an ' +
        'issuer that is not the one discovery was asked for, and every sign-in would fail.',
    );
  }
  return { issuer: `https://login.microsoftonline.com/${tenant.toLowerCase()}/v2.0`, ...credentials };
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
      const primary = Array.isArray(emails)
        ? emails.find((e) => e?.primary === true && e.verified === true && typeof e.email === 'string')
        : undefined;

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
