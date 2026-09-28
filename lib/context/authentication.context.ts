import { Injectable } from '@nestjs/common';
import { AuthenticationError } from '../errors/authentication.error.js';
import type { AuthenticatedSession, AuthenticatedUser, AuthenticationResult } from '../interfaces/authentication-result.interface.js';
import { AuthenticationScope } from './authentication-scope.service.js';

/**
 * The current user and session, readable from any singleton provider
 * without passing the request down. Correct in the handler and in
 * everything it calls or awaits, however many requests run at once. Empty
 * in middleware, guards and exception filters, in interceptors that run
 * before the module's own (an app's `APP_INTERCEPTOR` declared ahead of it:
 * read `@CurrentUser()` or `request.user` there), and outside requests.
 * A stream a handler returns but did not create (a shared `Subject`) runs
 * its operators in the scope of whoever emits: read the user before
 * building it.
 */
@Injectable()
export class AuthenticationContext<TUser = AuthenticatedUser, TSession = AuthenticatedSession> {
  constructor(private readonly scope: AuthenticationScope = new AuthenticationScope()) {}

  /** The user, or `null` when anonymous or outside a request. */
  get user(): TUser | null {
    return this.scope.current?.result?.user ?? null;
  }

  get session(): TSession | null {
    return this.scope.current?.result?.session ?? null;
  }

  get isAuthenticated(): boolean {
    return !!this.scope.current?.result?.user;
  }

  /**
   * The user, or an {@link AuthenticationError}: a 401 on any transport when
   * thrown under a handler, a plain error in a queue worker.
   */
  requireUser(): TUser {
    const user = this.user;
    if (!user) {
      throw new AuthenticationError();
    }
    return user;
  }

  /** Runs `fn` as `result.user`, for queue workers, cron jobs and tests. */
  run<R>(result: AuthenticationResult<TUser, TSession> | null, fn: () => R): R {
    return this.scope.run({ result }, fn);
  }
}
