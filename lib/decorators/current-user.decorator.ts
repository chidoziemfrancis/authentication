import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { getAuthState } from '../utils/auth-state.util.js';
import { scopedResult } from '../context/authentication-scope.service.js';
import type { AuthenticatedUser } from '../interfaces/authentication-result.interface.js';

/**
 * The authenticated user, or `null` on `@Public()` and anonymous optional
 * calls. `@CurrentUser('email')` picks one property; the key is checked
 * against the `AuthenticationTypes` augmentation.
 */
export const CurrentUser = createParamDecorator<keyof AuthenticatedUser | undefined>(
  (key, context: ExecutionContext) => {
    const user = resultOf(context)?.user ?? null;
    return key && user ? user[key] : user;
  },
);

/**
 * @internal This call's result: the scope the interceptor opened for it, else what the guard
 * recorded on the carrier. A ws message whose payload is a primitive shares nothing else with its
 * guard but the socket, which outlives it, and would otherwise read another message's user.
 */
export function resultOf(context: ExecutionContext) {
  const scoped = scopedResult(context);
  return scoped !== undefined ? scoped : getAuthState(context);
}
