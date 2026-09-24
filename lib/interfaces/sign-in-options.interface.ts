export interface SignInOptions {
  /**
   * How the user proved who they are, recorded on the `sign-in` event:
   * `password`, `magic-link`, `oidc:google`.
   */
  method?: string;
  /** Stored with the session, over what `session.metadata` returns for the request. */
  metadata?: Record<string, unknown>;
}
