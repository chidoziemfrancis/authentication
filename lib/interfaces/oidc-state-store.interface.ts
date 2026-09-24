import type { OidcTransaction } from './oidc.interface.js';

/**
 * Storage for logins in progress (PKCE verifier, nonce, return path),
 * keyed by `state`. Implement it on your database or Redis, and register
 * the provider with `AuthenticationStorage.registerSource({ oidcStates: this })`.
 *
 * `consumeOidcState()` must be one atomic get-and-delete
 * (`DELETE … RETURNING`, `GETDEL`), so a callback is accepted once. Anyone
 * can start a login, so the store must stay bounded: drop expired logins
 * as new ones are saved, and cap the rest.
 */
export interface OidcStateStore {
  /**
   * Saves a new login (a fresh random `state`: a plain insert), then keeps
   * the store bounded: deletes logins whose `expiresAt` is at or before this
   * one's `createdAt`, and past a cap, those that expire first.
   */
  saveOidcState(transaction: OidcTransaction): Promise<void>;
  /**
   * Removes and returns the login, in one atomic step; `undefined` if there
   * is none. Of several concurrent calls, exactly one gets the record.
   * Expired logins may be returned: `OidcService` checks expiry.
   */
  consumeOidcState(state: string): Promise<OidcTransaction | undefined>;
}
