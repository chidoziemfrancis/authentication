import type { Duration } from './duration.interface.js';

export interface MfaOptions {
  /**
   * Encryption of TOTP secrets at rest (AES-256-GCM): `{ keys: [key] }`,
   * newest key first. Required once `mfa` is configured: pass `false` to
   * store plaintext deliberately (tests, throwaway in-memory setups).
   */
  encryption: SecretEncryptionOptions | false;
  /** Shown in authenticator apps. */
  issuer?: string;
  /** Accepted 30-second steps either side of now: an integer from 0 to 10. Default 1, per RFC 6238 §5.2. */
  window?: number;
  /** Failed codes allowed per `lockoutWindow` before every code is refused: an integer of at least 1. Default 5. */
  maxAttempts?: number;
  /** Default `'15m'`. */
  lockoutWindow?: Duration;
  /** Recovery codes per batch: an integer of at least 1. Default 10. */
  recoveryCodes?: number;
  /**
   * How long a session that passed its first factor may wait for the second
   * (`mfa: 'pending'`) before it expires. Default `'10m'`, never more than
   * `session.absoluteTtl`. A pending cookie is half a credential: this keeps a
   * stolen one from staying useful for the session's full lifetime.
   */
  pendingTtl?: Duration;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface SecretEncryptionOptions {
  /**
   * AES-256-GCM keys: 32-byte `Buffer`s, or strings of at least 32
   * characters (random secrets, expanded with HKDF-SHA256; not passwords).
   * The first key encrypts, and every key decrypts. Prepend a new key to
   * rotate.
   */
  keys: (string | Buffer)[];
  /**
   * Accept stored values that are not ciphertext (secrets saved before
   * encryption was turned on) and re-encrypt them on the next successful
   * verification. Off by default: with encryption on, a plaintext value in
   * the store is otherwise indistinguishable from one an attacker planted.
   */
  migratePlaintext?: boolean;
}
