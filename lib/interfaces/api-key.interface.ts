export interface ApiKeyProviderOptions {
  /**
   * Starts every key, e.g. `cat` for `cat_<id>_<secret>`: 1-16 lowercase
   * letters and digits, starting with a letter. Secret scanners find leaked
   * keys by it; register it with yours (GitHub push protection, for one).
   */
  prefix: string;
  /** `realm` in the `WWW-Authenticate` challenge. Default `api`. */
  realm?: string;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

/** A new key, from `ApiKeyProvider.generate()`. */
export interface GeneratedApiKey {
  /** The whole key. Show it to its owner once, and store only `id` and `hash`. */
  key: string;
  /** The public part, which `findKey()` looks up: the key's row in your table. */
  id: string;
  /** SHA-256 of `key`, base64url. */
  hash: string;
}

/** A key as your table has it, returned by `ApiKeyProvider.findKey()`. */
export interface ApiKeyRecord<TUser> {
  /** The `hash` that `generate()` returned. */
  hash: string;
  /** Who the key acts as. */
  user: TUser;
  /** Refused from this moment on. */
  expiresAt?: Date | null;
}

/**
 * `@CurrentSession()` and `AuthenticationContext.session` for a request
 * signed in with an API key.
 */
export interface ApiKeySession {
  /** Tells this session from a `SessionRecord` or `JwtClaims`. */
  method: 'api-key';
  /** The key's public id. */
  keyId: string;
  expiresAt?: Date;
}
