import type { ProviderClass } from '../providers/authentication.provider.js';

export interface AuthenticateOptions {
  /**
   * Let anonymous callers through; `@CurrentUser()` is then `null`.
   * Credentials that are present are still verified, and bad ones get a
   * 401: silently ignoring an expired token would hide the signal to
   * refresh it.
   */
  optional?: boolean;
  /**
   * Require a verified second factor (step-up): a session that completed
   * MFA, or a JWT whose `amr` claim contains `mfa`, `otp` or `hwk`.
   */
  mfa?: boolean;
  /**
   * Require a user whose email address is verified: 403 `email_unverified`
   * otherwise. Checked with `EmailVerificationHandler.isVerified(user)`, or
   * `user.emailVerified === true` without a handler.
   */
  verifiedEmail?: boolean;
  /**
   * Only these providers may authenticate the route: classes, matched with
   * `instanceof`, so a base class such as `SessionCookieProvider` covers its
   * subclasses. Credentials of any other provider count as none.
   */
  providers?: ProviderClass[];
}

/** @internal What the guard reads: the class options, with the method's merged over them. */
export interface RouteAuthentication extends AuthenticateOptions {
  public?: boolean;
}
