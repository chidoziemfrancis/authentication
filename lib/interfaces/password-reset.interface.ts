import type { Duration } from './duration.interface.js';
import type { IssuedSession } from './session.interface.js';

/** The account behind an address, as `PasswordResetHandler.findUser()` returns it. */
export interface PasswordResetAccount {
  id: string;
  /**
   * The address the account has stored. The link goes there, never to the
   * address typed in the form: a lookup that ignores accents or dots (MySQL's
   * default collation does) would otherwise mail `victim@example.com`'s link
   * to whoever typed `victim@exämple.com`. A link works only while the
   * account keeps this address.
   */
  email: string;
  /**
   * The stored password hash, or `null` for an account without a password
   * (a reset then sets one). A link only works while this is unchanged, so
   * any password change invalidates the links sent before it.
   */
  passwordHash: string | null;
}

/** What `PasswordResetHandler.send()` delivers. */
export interface PasswordResetLink {
  userId: string;
  email: string;
  /** `passwordReset.url` with `?token=…`. */
  url: string;
  expiresAt: Date;
}

export interface PasswordResetOptions {
  /** Page that receives `?token=…`, asks for a new password and POSTs both, e.g. `https://app.example.com/reset-password`. */
  url: string;
  /** Lifetime of a link. Default `'1h'`. */
  ttl?: Duration;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface ResetPasswordOptions {
  /**
   * Signs the user in on this browser afterwards, through
   * `SignInService.signIn()` (so a user with an authenticator gets a
   * pending session). Default `false`.
   */
  signIn?: boolean;
}

export interface PasswordResetResult {
  userId: string;
  /** With `signIn: true`: the new session, as `SignInService.signIn()` returns it. */
  signedIn?: IssuedSession;
}
