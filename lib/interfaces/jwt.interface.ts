import type { Duration } from './duration.interface.js';

/**
 * Supported JWS algorithms. EdDSA means Ed25519 only: Ed448 is rejected
 * (untested here, and rare in practice).
 */
export type JwsAlgorithm = 'HS256' | 'RS256' | 'ES256' | 'EdDSA';

export interface JwtClaims {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  [claim: string]: unknown;
}

export interface ClaimRules {
  issuer?: string;
  /**
   * Accepted `aud` values. `false` accepts any audience, for tokens that
   * carry none (check the claim that names your client in `validate()`).
   */
  audience?: string | string[] | false;
  /**
   * Leeway for `exp`, `nbf` and `iat`. Default `0`, right for the app's own
   * tokens. Set it (`'30s'`) for another issuer's: a clock a second ahead
   * would otherwise issue tokens "in the future".
   */
  clockTolerance?: Duration;
  /** Reject tokens issued longer ago than this (needs `iat`). */
  maxAge?: Duration;
  /** Claims that must be present. `exp` is required by default. */
  required?: string[];
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}
