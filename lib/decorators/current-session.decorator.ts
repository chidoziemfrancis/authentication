import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { getAuthState } from '../utils/auth-state.util.js';

/** The provider's session object (stored record, JWT claims, API key row), or `null`. */
export const CurrentSession = createParamDecorator((_: unknown, context: ExecutionContext) => {
  return getAuthState(context)?.session ?? null;
});
