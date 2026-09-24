import type { Duration } from './duration.interface.js';

export interface RefreshTokenOptions {
  /** Lifetime of one refresh token. Default `'30d'`. */
  ttl?: Duration;
  /** Maximum lifetime of a family, however often it rotates. Default `'90d'`. */
  absoluteTtl?: Duration;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export type RefreshTokenFailure = 'invalid' | 'expired' | 'reused';
