import type { IncomingHttpHeaders } from 'node:http';
import type { CookieAttributes } from '../session/cookies.util.js';
import type { Duration } from './duration.interface.js';
import type { SessionRecord } from './session-store.interface.js';

/** The request a session is created from, as Express and Fastify both provide it. */
export interface SessionRequest {
  headers: IncomingHttpHeaders;
  ip?: string;
}

export interface SessionOptions {
  /**
   * Default `__Host-sid`, or `sid` when `cookie` rules the `__Host-` prefix
   * out (`secure: false`, a `domain`, or a `path` other than `/`).
   */
  cookieName?: string;
  /** Absolute lifetime: activity never extends a session past it. Default `'7d'`. */
  absoluteTtl?: Duration;
  /** Idle timeout, slid by activity. Default `'1d'`. `0` disables it. */
  idleTtl?: Duration;
  /** Write `lastActiveAt` at most this often, which saves a write per request. Default `'1m'`. */
  touchInterval?: Duration;
  /**
   * `HttpOnly` is always set. `secure` defaults to `true`, which browsers
   * accept from `http://localhost` too; turn it off only for plain HTTP on
   * another host.
   */
  cookie?: CookieAttributes;
  /**
   * Origins besides the application's own whose pages may use the session
   * cookie for unsafe requests (POST, …) and sign in, e.g.
   * `['https://app.example.com']` for a web app on another origin than the
   * API. The same list as `app.enableCsrfProtection({ trustedOrigins })`.
   */
  trustedOrigins?: string[];
  /**
   * What each new session stores next to the user, read from the request
   * that signs in (password, magic link, OIDC alike): a user agent, an IP
   * address, a device name, for "where you're signed in" pages.
   */
  metadata?: (request: SessionRequest) => Record<string, unknown>;
  /** Clock in epoch milliseconds, for tests. */
  now?: () => number;
}

export interface IssuedSession {
  session: SessionRecord;
  /** The raw token. Only the `Set-Cookie` value should leave the server. */
  token: string;
  /** `Set-Cookie` header value. `SignInService` sets it on the HTTP response itself. */
  cookie: string;
}
