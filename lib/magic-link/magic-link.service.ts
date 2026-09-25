import { Inject, Injectable, Optional } from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { firstHeader } from '../utils/auth-state.util.js';
import { AuthenticationScope } from '../context/authentication-scope.service.js';
import { AuthenticationRegistry } from '../services/authentication-registry.service.js';
import { AuthenticationStorage } from '../storage/authentication.storage.js';
import { AUTHENTICATION_MODULE_OPTIONS } from '../authentication.constants.js';
import { TOKEN_PATTERN, randomToken, safeEqual, safeRedirectPath, sha256 } from '../utils/crypto.util.js';
import { durationOr } from '../utils/duration.util.js';
import { AuthenticationEvents } from '../events/authentication-events.service.js';
import type { AuthenticationMagicLinkRefusedEvent } from '../events/authentication-events.interface.js';
import { requireUrlOption } from '../utils/options.util.js';
import { defaultCookieName, readCookie, serializeCookie } from '../session/cookies.util.js';
import type { IssuedSession } from '../interfaces/session.interface.js';
import { SignInService } from '../session/sign-in.service.js';
import type { MagicLinkOptions, MagicLinkRequest, CreatedMagicLink } from '../interfaces/magic-link.interface.js';
import { MagicLinkError } from '../errors/magic-link.error.js';
import { MagicLinkHandler } from './magic-link.handler.js';
import { normalizeEmail } from '../account/email.util.js';

/**
 * Passwordless sign-in links: 256-bit single-use tokens, stored hashed,
 * short-lived, and bound to the browser that requested them.
 *
 * Point the link at a page that POSTs the token back: mail scanners and
 * link previews follow GET links, and would burn (or use) the token.
 *
 * Like `OidcService`, the service binds each link to the browser that
 * requested it: `create()` sets an `HttpOnly`, `SameSite=Lax` cookie,
 * `__Host-magic_link_tx`, holding the link's id (the SHA-256 of the token,
 * which is what the store keys the link by and which signs nobody in by
 * itself), and `consume()` requires the same value in the cookie. The
 * `__Host-` prefix keeps sibling subdomains from planting one. So the
 * link's page must be on the same site as the API, as the session cookie
 * requires anyway, and a link forwarded to another browser or device is
 * refused there while it stays usable where it was requested. See
 * `magicLink.bindToBrowser`.
 */
@Injectable()
export class MagicLinkService {
  private readonly options?: MagicLinkOptions;
  private readonly ttl: number;
  private readonly bindToBrowser: boolean;
  private readonly txCookieName: string;

  constructor(
    private readonly storage: AuthenticationStorage,
    private readonly registry: AuthenticationRegistry,
    private readonly signIn: SignInService,
    @Optional() @Inject(AUTHENTICATION_MODULE_OPTIONS) options?: { magicLink?: MagicLinkOptions },
    private readonly scope: AuthenticationScope = new AuthenticationScope(),
    @Optional() private readonly adapterHost?: HttpAdapterHost,
    private readonly events: AuthenticationEvents = new AuthenticationEvents(),
  ) {
    this.options = options?.magicLink;
    if (this.options) {
      requireUrlOption(this.options.url, 'magicLink.url', 'the page that receives the link');
    }
    this.ttl = durationOr(this.options?.ttl, '15m');
    this.bindToBrowser = this.options?.bindToBrowser !== false;
    this.txCookieName = defaultCookieName('magic_link_tx', this.options?.cookie);
  }

  /**
   * Creates a link and hands it to `MagicLinkHandler.send()`. The token is
   * not returned. Called from an HTTP handler, it sets the transaction
   * cookie on the response (see `bindToBrowser`); the returned `cookie` is
   * that `Set-Cookie` value, for callers outside HTTP. An `email` that isn't
   * a non-blank string (a request body without it) creates and sends nothing,
   * and gets the same answer, like `PasswordResetService.request()`.
   */
  async create(email: string, { redirectTo }: { redirectTo?: string } = {}): Promise<CreatedMagicLink> {
    const { options, handler } = this.feature();
    const now = this.now();
    const expiresAt = new Date(now + this.ttl);

    const normalized = typeof email === 'string' ? normalizeEmail(email) : '';
    if (normalized === '') {
      return { expiresAt };
    }

    const token = randomToken();
    const safe = safeRedirectPath(redirectTo);
    const id = sha256(token);
    await this.storage.magicLinks.saveMagicLink({
      id,
      email: normalized,
      createdAt: new Date(now),
      expiresAt,
      ...(safe && { redirectTo: safe }),
    });

    let cookie: string | undefined;
    if (this.bindToBrowser) {
      cookie = this.txCookie(id, this.ttl / 1000);
      this.setCookie(cookie);
    }

    const url = new URL(options.url);
    url.searchParams.set('token', token);
    await handler.send({ email: normalized, url: url.toString(), expiresAt });

    return { expiresAt, ...(cookie && { cookie }) };
  }

  /**
   * Burns the token, asks `MagicLinkHandler.resolveUser()` for the user, and
   * signs them in on this browser through `SignInService`, which sets the
   * cookie. `null` for unknown, used or expired tokens and for addresses
   * the handler refuses, one answer for all of them. A link this browser
   * did not request (see `bindToBrowser`) throws {@link MagicLinkError}
   * instead, before anything is looked up or burned: the module answers it
   * with a 401 that tells the customer where to open the link. Each
   * refusal is a `magic-link-refused` event with its reason. Outside an
   * HTTP handler, pass the `request` that carries the cookie.
   */
  async consume(
    token: string,
    { request }: { request?: MagicLinkRequest } = {},
  ): Promise<(IssuedSession & { redirectTo?: string }) | null> {
    const { handler } = this.feature();
    if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
      return this.refuse('unknown');
    }

    const id = sha256(token);
    if (this.bindToBrowser) {
      const req = request ?? this.scope.exchange()?.request;
      const bound = readCookie(firstHeader(req?.headers, 'cookie'), this.txCookieName);
      // The cookie stays: it may belong to a link this browser did request, and the link stays
      // for the browser that did. Nothing is looked up: a link was presented, not proved.
      if (!bound || !safeEqual(bound, id)) {
        this.events.emit({ type: 'magic-link-refused', reason: 'not-this-browser' });
        throw new MagicLinkError();
      }
    }

    const record = await this.storage.magicLinks.consumeMagicLink(id);
    // This browser's link is settled either way: the cookie goes.
    this.setCookie(this.txCookie('', 0));

    if (!record) {
      return this.refuse('unknown');
    }
    if (this.now() >= record.expiresAt.getTime()) {
      return this.refuse('expired', record.email);
    }
    const user = await handler.resolveUser(record.email);
    if (!user) {
      return this.refuse('refused', record.email);
    }

    const issued = await this.signIn.signIn(user.id, { method: 'magic-link' });
    return { ...issued, redirectTo: record.redirectTo };
  }

  /** The options and the handler; the module refuses to start with one and not the other. */
  private feature(): { options: MagicLinkOptions; handler: MagicLinkHandler } {
    const handler = this.registry.handler('magicLink');
    if (!this.options || !handler) {
      throw new Error(
        'MagicLinkService: magic links are not enabled. Configure `magicLink` in the AuthenticationModule options, and ' +
          "register a MagicLinkHandler: `registry.registerHandler('magicLink', this)`.",
      );
    }
    return { options: this.options, handler };
  }

  /** The generic answer: which refusal it was is told only by the event. */
  private refuse(reason: Exclude<AuthenticationMagicLinkRefusedEvent['reason'], 'not-this-browser'>, email?: string): null {
    this.events.emit({ type: 'magic-link-refused', reason, ...(email && { email }) });
    return null;
  }

  private txCookie(value: string, maxAge: number): string {
    return serializeCookie(this.txCookieName, value, { ...this.options?.cookie, sameSite: 'lax', maxAge });
  }

  private setCookie(cookie: string) {
    if (!this.bindToBrowser) {
      return;
    }
    const response = this.scope.exchange()?.response;
    if (response) {
      this.adapterHost?.httpAdapter?.appendHeader(response, 'Set-Cookie', cookie);
    }
  }

  private now() {
    return this.options?.now?.() ?? Date.now();
  }
}
