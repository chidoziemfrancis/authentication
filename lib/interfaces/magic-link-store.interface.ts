export interface MagicLinkRecord {
  /**
   * SHA-256 of the token, and of the secret that binds the link to the
   * browser that requested it (`magicLink.bindToBrowser`): the link alone
   * does not find it.
   */
  id: string;
  email: string;
  createdAt: Date;
  expiresAt: Date;
  redirectTo?: string;
}

/**
 * Storage for pending magic links. Implement it on your database or Redis,
 * and register the provider with
 * `AuthenticationStorage.registerSource({ magicLinks: this })`.
 *
 * `consumeMagicLink()` must be one atomic get-and-delete
 * (`DELETE … RETURNING`, `GETDEL`), so a link works once however many
 * requests present it. Anyone can request links, so the store must stay
 * bounded: drop expired links as new ones are saved, and cap the rest.
 */
export interface MagicLinkStore {
  /**
   * Saves a new link (a fresh random id: a plain insert), then keeps the
   * store bounded: deletes links whose `expiresAt` is at or before this
   * one's `createdAt`, and past a cap, those that expire first.
   */
  saveMagicLink(record: MagicLinkRecord): Promise<void>;
  /**
   * Removes and returns the link, in one atomic step; `undefined` if there
   * is none. Of several concurrent calls, exactly one gets the record.
   * Expired links may be returned: `MagicLinkService` checks expiry.
   */
  consumeMagicLink(id: string): Promise<MagicLinkRecord | undefined>;
}
