import type { Duration } from './duration.interface.js';

/** What `EmailVerificationHandler.send()` delivers. */
export interface EmailVerificationLink {
  userId: string;
  /** The address to verify, and to send the link to. */
  email: string;
  /** `emailVerification.url` with `?token=…`. */
  url: string;
  expiresAt: Date;
}

export interface EmailVerificationOptions {
  /** Page that receives `?token=…` and POSTs it back, e.g. `https://app.example.com/verify-email`. */
  url: string;
  /** Lifetime of a link. Default `'24h'`. */
  ttl?: Duration;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}
