import type { ExecutionContext } from '@nestjs/common';
import { firstHeader, getRequestHeaders } from '../utils/auth-state.util.js';
import type { AuthenticatedSession, AuthenticatedUser, AuthenticationResult } from '../interfaces/authentication-result.interface.js';

/**
 * A credential source: the contract every provider meets, and the base
 * class of `SessionCookieProvider` and `JwtBearerProvider`.
 *
 * - Resolve to `null` when the request carries no credentials this provider
 *   understands; the guard tries the next provider.
 * - Throw `AuthenticationError` when credentials are present but invalid;
 *   the guard answers 401, even on `@Authenticate({ optional: true })`
 *   routes.
 *
 * Subclasses are ordinary `@Injectable()` classes: they can live in any
 * module and inject repositories, config, etc. The same class serves HTTP,
 * GraphQL, WebSockets and RPC, because it receives the `ExecutionContext`.
 */
// oxlint-disable-next-line typescript/no-unsafe-declaration-merging -- see the interface below
export abstract class AuthenticationProvider<TUser = AuthenticatedUser, TSession = AuthenticatedSession> {
  abstract authenticate(
    context: ExecutionContext,
  ): Promise<AuthenticationResult<TUser, TSession> | null> | AuthenticationResult<TUser, TSession> | null;

  /**
   * A request header, whatever the transport: the HTTP request, GraphQL's
   * `context.req`, or the WebSocket handshake. `undefined` over RPC, whose
   * metadata is transport specific. A repeated header gives its first value.
   */
  protected header(context: ExecutionContext, name: string): string | undefined {
    return firstHeader(getRequestHeaders(context), name.toLowerCase());
  }
}

// Declared on the interface, so the base class emits no `challenge` field
// that would shadow a subclass method. Merging requires the class's type
// parameters, unused here.
// oxlint-disable-next-line no-unused-vars
export interface AuthenticationProvider<TUser = AuthenticatedUser, TSession = AuthenticatedSession> {
  /** `WWW-Authenticate` challenge sent with a 401 when no provider found credentials. */
  challenge?(context: ExecutionContext): string | undefined;
}

/** A provider class, possibly abstract (`SessionCookieProvider`), for `@Authenticate({ providers })`. */
export type ProviderClass = abstract new (...args: any[]) => AuthenticationProvider<any, any>;

/**
 * @internal Called by the module once the provider is resolved, before the
 * first request, so a misconfigured provider fails at startup. `resolve`
 * looks up the module's providers, for instances created with `new` (which
 * Nest did not property-inject).
 */
export const PROVIDER_INIT = Symbol('nestjs.authentication.provider-init');

/** @internal */
export type ProviderInit = (resolve: <T>(token: string | symbol | (abstract new (...args: any[]) => T)) => T) => void;
