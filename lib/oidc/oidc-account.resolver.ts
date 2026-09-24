import type { OAuthTokens, OidcProfile } from '../interfaces/oidc-provider.interface.js';
import type { OidcResolveContext } from '../interfaces/oidc.interface.js';

/**
 * Implemented by the app: maps an external identity to a local user
 * (find by `(provider, subject)`, link, or create). Return `null` to refuse.
 * An ordinary provider of one of your modules, which registers itself from
 * its constructor: `registry.registerHandler('oidc', this)`.
 *
 * Linking a new identity to an existing account by email is only safe when
 * both sides verified the address: `profile.emailVerified` (the provider
 * asserted it) and your own record (the owner proved it to you). Otherwise
 * someone could register the address first, with a password of their
 * choosing, and keep access once the real owner signs in with the provider
 * (account pre-hijacking). Refuse, and let the user sign in and link from
 * their account (`context.linkTo`).
 */
export abstract class OidcAccountResolver {
  abstract resolveUser(
    profile: OidcProfile,
    tokens: OAuthTokens,
    context: OidcResolveContext,
  ): { id: string } | null | Promise<{ id: string } | null>;
}
