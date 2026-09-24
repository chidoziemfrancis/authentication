import type { MagicLink } from '../interfaces/magic-link.interface.js';

/**
 * Implemented by the app: delivery (the module ships no mailer) and the
 * email-to-user mapping (look up, or create for passwordless sign-up).
 * An ordinary provider of one of your modules, which registers itself from
 * its constructor: `registry.registerHandler('magicLink', this)`.
 *
 * The link proves the address, not that the account behind it was created
 * by the same person: if accounts can be registered without verifying the
 * email (password sign-up), refuse links to accounts whose address was
 * never verified, or someone who registered the address first keeps access
 * (account pre-hijacking).
 */
export abstract class MagicLinkHandler {
  abstract send(link: MagicLink): void | Promise<void>;
  abstract resolveUser(email: string): { id: string } | null | Promise<{ id: string } | null>;
}
