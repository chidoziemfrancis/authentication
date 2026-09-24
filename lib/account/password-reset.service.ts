import { Inject, Injectable, Logger, Optional, type OnModuleDestroy } from '@nestjs/common';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, safeEqual, sha256 } from '../utils/crypto.util.js';
import { durationOr } from '../utils/duration.util.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import { requireUrlOption } from '../utils/options.util.js';
import { TokenService } from '../jwt/token.service.js';
import { PasswordHasher } from '../services/password-hasher.service.js';
import { SessionService } from '../session/session.service.js';
import { SignInService } from '../session/sign-in.service.js';
import type {
  PasswordResetOptions,
  ResetPasswordOptions,
  PasswordResetResult,
} from '../interfaces/password-reset.interface.js';
import { normalizeEmail } from './email.util.js';
import { PasswordResetHandler } from './password-reset.handler.js';

/**
 * "Forgot your password?": reset links that are 256-bit single-use tokens,
 * stored hashed, short-lived, and bound to the address they were sent to and
 * to the password they replace.
 *
 * - `request(email)` answers the same way, at once, whether or not the
 *   address has an account: finding the account, storing the token and
 *   sending the link happen after it returned, so neither the answer nor
 *   its timing reveals which addresses are registered.
 * - `reset(token, password)` burns the token, stores the new password's
 *   hash, invalidates the user's other reset links, and ends every session
 *   and refresh-token family of the user (whoever knew the old password is
 *   signed out). It also marks the address verified when email
 *   verification is configured: the link proved it.
 *
 * Point the link at a page that asks for the new password and POSTs it with
 * the token: mail scanners and link previews follow GET links.
 */
@Injectable()
export class PasswordResetService implements OnModuleDestroy {
  private static readonly logger = new Logger('PasswordResetService');
  private readonly options?: PasswordResetOptions;
  private readonly ttl: number;
  private readonly inFlight = new Set<Promise<void>>();

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    private readonly hasher: PasswordHasher,
    private readonly sessions: SessionService,
    private readonly tokens: TokenService,
    private readonly signInService: SignInService,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { passwordReset?: PasswordResetOptions },
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.passwordReset;
    if (this.options) {
      requireUrlOption(this.options.url, 'passwordReset.url', 'the page that receives the link');
    }
    this.ttl = durationOr(this.options?.ttl, '1h');
  }

  /**
   * Starts a reset for `email`, if it belongs to an account: the link goes
   * to `PasswordResetHandler.send()`. Returns at once, before the account is
   * looked up, so the caller answers every address the same way and in the
   * same time. Failures are logged, not thrown. On shutdown, the module waits
   * for the requests in flight.
   */
  request(email: string): void {
    this.feature();
    if (typeof email !== 'string') {
      return;
    }

    const work = this.issue(normalizeEmail(email)).catch((error: unknown) =>
      PasswordResetService.logger.error('A password reset request failed', error instanceof Error ? error.stack : error),
    );
    this.inFlight.add(work);
    void work.finally(() => this.inFlight.delete(work));
  }

  /**
   * Sets a new password with a reset token. `null` (and nothing changed)
   * for an unknown, used or expired token, and for one whose account
   * changed its address or password since the link was sent.
   */
  async reset(token: string, password: string, { signIn = false }: ResetPasswordOptions = {}): Promise<PasswordResetResult | null> {
    const { handler } = this.feature();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token) || typeof password !== 'string') {
      return null;
    }

    const record = await this.storage.emailTokens.consumeEmailToken(sha256(token), 'password-reset');
    if (!record || this.now() >= record.expiresAt.getTime()) {
      return null;
    }
    const account = await handler.findUser(record.email);
    if (!account || account.id !== record.userId || !safeEqual(fingerprint(account.passwordHash), record.fingerprint ?? '')) {
      return null;
    }

    await handler.updatePassword(account.id, await this.hasher.hash(password));
    await this.storage.emailTokens.deleteUserEmailTokens(account.id, 'password-reset');
    await this.sessions.revokeAll(account.id);
    await this.tokens.revokeAll(account.id);
    // The link reached the address, and the password is the owner's now.
    await this.registry.handler('emailVerification')?.markVerified(account.id, record.email);
    this.events.emit({ type: 'password-reset', userId: account.id });

    const signedIn = signIn ? await this.signInService.signIn(account.id, { method: 'password-reset' }) : undefined;
    return { userId: account.id, ...(signedIn && { signedIn }) };
  }

  async onModuleDestroy() {
    await Promise.all(this.inFlight);
  }

  private async issue(email: string): Promise<void> {
    const { options, handler } = this.feature();
    const account = await handler.findUser(email);
    if (!account) {
      this.events.emit({ type: 'password-reset-requested', email });
      return;
    }

    const token = randomToken();
    const now = this.now();
    const expiresAt = new Date(now + this.ttl);
    await this.storage.emailTokens.saveEmailToken({
      id: sha256(token),
      purpose: 'password-reset',
      userId: account.id,
      email,
      fingerprint: fingerprint(account.passwordHash),
      createdAt: new Date(now),
      expiresAt,
    });
    this.events.emit({ type: 'password-reset-requested', email, userId: account.id });

    const url = new URL(options.url);
    url.searchParams.set('token', token);
    await handler.send({ userId: account.id, email, url: url.toString(), expiresAt });
  }

  /** The options and the handler; the module refuses to start with one and not the other. */
  private feature(): { options: PasswordResetOptions; handler: PasswordResetHandler } {
    const handler = this.registry.handler('passwordReset');
    if (!this.options || !handler) {
      throw new Error(
        'PasswordResetService: password reset is not enabled. Configure `passwordReset` in the AuthenticationModule ' +
          "options, and register a PasswordResetHandler: `registry.registerHandler('passwordReset', this)`.",
      );
    }
    return { options: this.options, handler };
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}

/** What a reset link remembers of the password it replaces. */
function fingerprint(passwordHash: string | null): string {
  return sha256(`nestjs-authentication password-reset v1 ${passwordHash ?? ''}`);
}
