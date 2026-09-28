export interface TotpRecord {
  /** Sealed secret (`v1.<keyId>.…`, see `SecretCipher`); base32 plaintext only with `encryption: false`. */
  secret: string;
  /** `false` until the user proved the authenticator works. */
  confirmed: boolean;
  /**
   * A replacement secret (sealed like `secret`) staged by
   * `enroll(…, { replace: true })`. `secret` stays active until `confirm()`
   * proves the new authenticator works.
   */
  pendingSecret?: string;
  /** Last accepted time step, for replay protection. */
  lastUsedStep?: number;
}

/**
 * Second-factor storage: each user's authenticator, recovery code hashes,
 * and failed attempts. Implement it on your database or Redis, and register
 * the provider with `AuthenticationStorage.registerSource({ mfa: this })`.
 *
 * Four methods are what stop a code from being accepted twice, or a burst
 * of guesses from outrunning the lockout, and must be single atomic writes
 * (a conditional update or delete, an upsert, a Lua script), never a read
 * followed by a write: `saveTotp()`, `claimTotpStep()`,
 * `consumeRecoveryCode()` and `recordMfaFailure()`. Each one's comment has
 * the race it prevents, and `authenticationStoreContract()` from
 * `@nestjs/authentication/testing` checks them (`concurrent: true`).
 *
 * Times (`now`) are epoch milliseconds from `MfaService`'s clock, never the
 * store's. Optional fields come back absent (`undefined`), never `null`.
 */
export interface MfaStore {
  getTotp(userId: string): Promise<TotpRecord | undefined>;
  /**
   * Saves the user's authenticator (an upsert), or deletes it (`null`).
   * Never lowers the stored `lastUsedStep`: keep the larger of the stored
   * one and the record's (`GREATEST()` in the upsert). A record read before
   * a concurrent `claimTotpStep()` must not reopen the step it claimed.
   */
  saveTotp(userId: string, record: TotpRecord | null): Promise<void>;
  /**
   * Sets `lastUsedStep = step` iff the user has an authenticator and `step`
   * is greater than the stored one (or none is stored), in one conditional
   * write; `true` if it did. Of several concurrent calls with the same step,
   * exactly one gets `true`: a TOTP code works once.
   */
  claimTotpStep(userId: string, step: number): Promise<boolean>;
  /** Replaces the user's recovery code hashes with `hashes` (`[]` deletes them). */
  saveRecoveryCodes(userId: string, hashes: string[]): Promise<void>;
  /**
   * Removes one recovery code hash of this user, in one conditional delete;
   * `true` if this call removed it. Of several concurrent calls, exactly one
   * gets `true`.
   */
  consumeRecoveryCode(userId: string, hash: string): Promise<boolean>;
  countRecoveryCodes(userId: string): Promise<number>;
  /**
   * Records a failed attempt at `now`, then returns the failures within
   * `windowMs` before `now` (`at > now - windowMs`), this one included.
   * Record first, count second, each visible to other callers as soon as it
   * returns: parallel calls each count every attempt recorded before them,
   * so no more than `n` of them see a count of `n` or less. `MfaService`
   * calls it *before* checking a code, which is what stops a burst of
   * parallel guesses.
   */
  recordMfaFailure(userId: string, windowMs: number, now: number): Promise<number>;
  /** The failures within `windowMs` before `now`, without recording one. */
  countMfaFailures(userId: string, windowMs: number, now: number): Promise<number>;
  /** Forgets the user's failures (after a code verified). */
  clearMfaFailures(userId: string): Promise<void>;
}
