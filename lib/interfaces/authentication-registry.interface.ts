import type { EmailVerificationHandler } from '../account/email-verification.handler.js';
import type { PasswordResetHandler } from '../account/password-reset.handler.js';
import type { MagicLinkHandler } from '../magic-link/magic-link.handler.js';
import type { OidcAccountResolver } from '../oidc/oidc-account.resolver.js';
import type { AuthenticationProvider } from '../providers/authentication.provider.js';

/**
 * The feature handlers, by the name of the module option each one goes
 * with: what `registerHandler()` takes. A feature needs both, its option and
 * its handler, or the module refuses to start.
 */
export interface AuthenticationHandlers {
  /** Delivers verification links and records verified addresses. */
  emailVerification: EmailVerificationHandler;
  /** Finds accounts, delivers reset links and stores new passwords. */
  passwordReset: PasswordResetHandler;
  /** Delivers magic links and maps an address to a user. */
  magicLink: MagicLinkHandler;
  /** Maps an OpenID Connect identity to a user. */
  oidc: OidcAccountResolver;
}

export type AuthenticationHandlerName = keyof AuthenticationHandlers;

/** `registerProvider()` options. */
export interface RegisterProviderOptions {
  /**
   * Where the provider runs in the chain: ascending, the first provider that
   * returns a user wins. Default `0`. Two providers can't share an order.
   */
  order?: number;
  /** Replace the provider registered at the same `order` (tests, a wrapper around it). */
  replace?: boolean;
}

/** `registerHandler()` options. */
export interface RegisterHandlerOptions {
  /** Replace the handler already registered for the feature (tests, a wrapper around it). */
  replace?: boolean;
}

/**
 * What the guard calls: an `AuthenticationProvider` subclass, or any object
 * with its `authenticate()` (and optional `challenge()`).
 */
export type CredentialProvider<TUser = any, TSession = any> = Pick<AuthenticationProvider<TUser, TSession>, 'authenticate' | 'challenge'>;
