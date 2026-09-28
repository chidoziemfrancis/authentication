import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import { resultOf } from './current-user.decorator.js';

/** The provider's session object (a `SessionRecord`, JWT claims, an `ApiKeySession`), or `null`. */
export const CurrentSession = createParamDecorator((_: unknown, context: ExecutionContext) => {
  return resultOf(context)?.session ?? null;
});
