import type { JwsAlgorithm } from './jwt.interface.js';

export interface OidcProfile {
  /** Config key of the provider (`google`, `github`, …). */
  provider: string;
  /** Stable account id at the provider. Link accounts by (provider, subject), never by email. */
  subject: string;
  email?: string;
  /** Only `true` when the provider asserted it. Unverified emails must not link accounts. */
  emailVerified: boolean;
  name?: string;
  picture?: string;
  /** Verified ID token claims merged with userinfo (OIDC), or the raw userinfo (OAuth 2.0). */
  claims: Record<string, unknown>;
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresIn?: number;
  scope?: string;
}

export interface ProfileContext {
  provider: string;
  tokens: OAuthTokens;
  /** GET with the access token, JSON response. For extra API calls. */
  fetchJson(url: string): Promise<any>;
}

export interface OidcProviderConfig {
  /** `oidc` (default): discovery + ID token. `oauth2`: plain OAuth 2.0 (GitHub), profile from an API. */
  kind?: 'oidc' | 'oauth2';
  /** OIDC issuer; discovery is `${issuer}/.well-known/openid-configuration`. */
  issuer?: string;
  clientId: string;
  clientSecret?: string;
  /** Default `openid email profile` for OIDC. */
  scopes?: string[];
  /** Override or (for `oauth2`) supply endpoints. */
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userinfoEndpoint?: string;
  jwksUri?: string;
  /** Accepted ID token algorithms. Default `RS256`, `ES256`. */
  idTokenAlgorithms?: JwsAlgorithm[];
  /** Default `client_secret_basic` with a secret, `none` without (public client + PKCE). */
  tokenEndpointAuthMethod?: 'client_secret_basic' | 'client_secret_post' | 'none';
  /**
   * Extra authorization request parameters (`prompt`, `hd`, `login_hint`,
   * …). They travel through the browser, which can change or drop them:
   * hints to the provider, never checks. Check what they ask for in the
   * resolver, on the verified claims (`profile.claims.hd`, `acr`,
   * `auth_time`).
   */
  authorizationParams?: Record<string, string>;
  /** `oauth2` only: builds the profile from the userinfo response. */
  profile?(userinfo: any, context: ProfileContext): OidcProfile | Promise<OidcProfile>;
}
