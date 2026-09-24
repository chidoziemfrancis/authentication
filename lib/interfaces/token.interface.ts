export interface IssueTokensOptions {
  /**
   * Claims that describe the sign-in (`amr`, `auth_time`, …): this access
   * token and every one `refresh()` mints carry them. Keep roles and other
   * facts that can change out of them: they are fixed for the family's life.
   * The service owns the `amr` values that mean a second factor (`mfa`,
   * `otp`, `hwk`): it adds `mfa` itself once a code was verified, and drops
   * them from `claims.amr` with a warning (the rest, `pwd`, `sso`, is kept).
   */
  claims?: Record<string, unknown>;
  /** How the user proved who they are, recorded on the `sign-in` event: `password`, `magic-link`. */
  method?: string;
  /**
   * The code the client sent for a user with a confirmed authenticator: a
   * TOTP `code` or a `recoveryCode`. Ignored for other users.
   */
  secondFactor?: { code?: string; recoveryCode?: string };
}

/** What a token endpoint returns to a client that signed in. */
export interface TokenPair {
  /** A JWT signed with the `accessToken` options. */
  accessToken: string;
  /** Opaque, single use: `refresh()` exchanges it for a new pair. */
  refreshToken: string;
  /** Seconds until the access token expires (OAuth's `expires_in`). */
  expiresIn: number;
}
